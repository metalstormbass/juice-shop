import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .agents import Agents, evidence
from .config import Config, load
from .github import GitHub, issue_payload
from .inventory import collect, compare
from .models import Inventory, Repository
from .osv import OSV
from .reconcile import reconcile
from .remediation import candidates, remediate
from .store import SQLiteStore, encoded


def revision(root, ref):
    return subprocess.check_output(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"],
                                   cwd=root, text=True, timeout=15).strip()


def read_inventory(root, repository, ref=None):
    path = root / repository.lockfile
    if ref:
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            path.write_bytes(subprocess.check_output(
                ["git", "show", f"{repository.revision}:{repository.lockfile}"], cwd=root, timeout=30))
            return collect(path, repository)
    if not path.resolve().is_relative_to(root):
        raise ValueError("Lockfile resolves outside checkout")
    return collect(path, repository)


def emit(value):
    print(json.dumps(json.loads(encoded(value)), indent=2))


def main():
    parser = argparse.ArgumentParser(prog="appsec")
    parser.add_argument("command", choices=["inventory", "scan", "triage", "hunt", "validate", "reconcile",
                                           "remediate", "report", "compare"])
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--db", type=Path, default=Path("appsec.sqlite"))
    parser.add_argument("--inventory-out", type=Path)
    parser.add_argument("--base-inventory", type=Path)
    parser.add_argument("--base-ref")
    parser.add_argument("--ref")
    parser.add_argument("--finding-id")
    parser.add_argument("--apply", action="store_true", help="Allow GitHub writes on the verified default revision")
    parser.add_argument("--dry-run", action="store_false", dest="apply")
    parser.set_defaults(apply=False)
    args = parser.parse_args()
    try:
        return execute(args)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "error", "type": type(error).__name__,
                          "detail": str(error) if isinstance(error, FileNotFoundError) else "operation failed"}),
              file=sys.stderr)
        return 1


def execute(args, scanner=None, github=None, agent_send=None):
    root = args.root.resolve()
    config = load(args.config) if args.config else Config()
    if config.repository == "local/repository" and os.environ.get("GITHUB_REPOSITORY"):
        config = Config.model_validate({**config.model_dump(), "repository": os.environ["GITHUB_REPOSITORY"]})
    store = SQLiteStore(args.db)
    if args.command == "report":
        emit({namespace: store.all(namespace) for namespace in ("run", "attempts", "pull", "validation")})
        return 0
    sha = revision(root, args.ref or "HEAD")
    repo = Repository(slug=config.repository, lockfile=config.lockfile, revision=sha)
    scope = f"{repo.slug}:{repo.lockfile}"
    if args.apply and args.command in ("reconcile", "remediate"):
        token = os.environ.get("GITHUB_TOKEN")
        if github is None and not token:
            raise ValueError("Set GITHUB_TOKEN for --apply")
        github = github or GitHub(repo.slug, token)
        if github.default_head()[1] != sha or subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, timeout=15).strip():
            raise ValueError("GitHub writes require a clean default-branch checkout")
        args.ref = sha
    else:
        github = None
    inventory = read_inventory(root, repo, args.ref)
    previous = store.get("inventory", scope)
    if args.base_inventory:
        previous = json.loads(args.base_inventory.read_text())
    if args.base_ref:
        base = repo.model_copy(update={"revision": revision(root, args.base_ref)})
        try:
            previous = read_inventory(root, base, args.base_ref).model_dump()
        except subprocess.CalledProcessError:
            # Allow a PR to introduce the first lockfile; other read errors still fail closed.
            tree = subprocess.check_output(["git", "ls-tree", base.revision, "--", base.lockfile],
                                           cwd=root, timeout=15)
            if tree:
                raise
            previous = None
    baseline = Inventory.model_validate(previous) if previous else None
    if baseline and (baseline.repository.slug, baseline.repository.lockfile) != (repo.slug, repo.lockfile):
        raise ValueError("Inventory baseline belongs to a different repository or lockfile")
    changes = compare(baseline, inventory)
    store.put("inventory", scope, inventory)
    if args.inventory_out:
        args.inventory_out.write_text(encoded(inventory) + "\n")
    summary = {"dependencies": len(inventory.dependencies), "changes": changes,
               "coverage_gaps": [dep.path for dep in inventory.dependencies
                                 if dep.registry.source != "public-npm"]}
    if args.command == "inventory":
        emit(summary)
        return 0
    scanner = scanner or OSV(store=store)
    findings = scanner.scan(inventory)
    summary["findings"] = [finding.model_dump(exclude={"advisories"}) for finding in findings]
    if args.command in ("scan", "compare"):
        for finding in findings:
            store.put("finding", finding.finding_id, finding)
        store.put("run", scope, summary)
        emit(summary)
        return 0
    agents = Agents(store, config, os.environ.get("OPENAI_API_KEY"),
                    **({"send": agent_send} if agent_send else {}))
    findings = reconcile(root, inventory, findings, store, agents, github)
    states = store.all("state:" + scope)
    summary["states"] = {key: state["status"] for key, state in states.items()}
    if args.command in ("triage", "hunt", "validate", "remediate") and args.finding_id:
        finding = next((item for item in findings if item.finding_id == args.finding_id), None)
        if finding is None:
            raise ValueError("Finding is absent from the current scan")
        state = states[finding.finding_id]
        refs = evidence(root, finding.package)
        assessment = state["display"].get("assessment")
        if args.command == "hunt":
            result = agents.run("hunt", finding, refs, assessment=assessment)
            summary["investigation"] = result.model_dump() if result else None
        if args.command == "validate":
            result = state["display"].get("validation") or {"result": "unable to validate", "evidence_ids": [],
                    "checks": ["No behavior test has been approved for this finding."]}
            store.put("validation", finding.finding_id, result)
            summary["validation"] = result
        if args.command == "remediate":
            if state["status"] in ("remediation-in-progress", "risk-accepted") or state.get("attempted_revision") == sha:
                emit({"finding_id": finding.finding_id, "status": state["status"]})
                return 0
            if args.ref is None and read_inventory(root, repo, sha).dependencies != inventory.dependencies:
                raise ValueError("Remediation requires a committed lockfile matching the working tree")
            advice = agents.run("remediation", finding, refs, assessment=assessment,
                                candidates=candidates(finding))
            if not candidates(finding) or (advice and advice.recommendation != "upgrade"):
                summary["escalation"] = "No approved compatible upgrade candidate"
                files = {}
                attempts = []
            else:
                proposal = agents.run("test-development", finding, refs, assessment=assessment)
                if proposal:
                    summary["test_proposal"] = proposal.model_dump()
                attempts, files = remediate(root, repo, inventory, findings, finding, config, scanner)
                summary["attempts"] = [item.model_dump() for item in attempts]
                store.put("attempts", finding.finding_id, summary["attempts"])
                if not files:
                    summary["escalation"] = "No candidate passed independent verification"
            if not files and github:
                issue = github.call("GET", f"/issues/{store.get('issue', finding.finding_id)}")
                state = {**state, "status": "needs-human-review", "reason": summary["escalation"],
                         "attempted_revision": sha,
                         "display": {**state["display"], "remediation_attempts": summary.get("attempts", [])}}
                github.sync(issue, issue_payload(finding, state))
                store.put("state:" + scope, finding.finding_id, state)
            if files:
                story = agents.run("pr", finding, refs, assessment=assessment,
                                   validation=attempts[-1].model_dump())
                narrative = story.model_dump() if story else {"exposure": assessment, "residual_risks": "Human review required"}
                summary["draft"] = {"files": sorted(files), "validation": attempts[-1].model_dump(),
                                    "narrative": narrative}
                if github:
                    issue_number = store.get("issue", finding.finding_id)
                    issue = github.call("GET", f"/issues/{issue_number}")
                    pull = github.draft(repo, issue, finding, files, attempts[-1], narrative)
                    store.put("pull", finding.finding_id, pull)
                    state = {**state, "status": "remediation-in-progress", "pull": pull.number,
                             "reason": "Draft remediation PR exists"}
                    store.put("state:" + scope, finding.finding_id, state)
                    github.sync(issue, issue_payload(finding, state, validation=attempts[-1].model_dump()))
                    summary["pull"] = pull.model_dump()
    elif args.command == "remediate":
        raise ValueError("Remediation requires --finding-id")
    summary["states"] = {key: state["status"] for key, state in store.all("state:" + scope).items()}
    summary["openai_calls"] = config.agent_calls - agents.remaining
    summary["metrics"] = store.agent_metrics()
    store.put("run", scope, summary)
    emit(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
