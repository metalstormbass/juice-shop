import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .agents import Agents, evidence
from .exposure import chains, options_for
from .config import Config, load
from .github import GitHub, issue_payload
from .inventory import collect, compare
from .models import Inventory, Repository
from .osv import OSV
from .reconcile import reconcile
from .remediation import candidates, remediate
from .store import SQLiteStore, digest as evidence_digest, encoded


def inspect_fix(agents, repo, inventory, finding, refs, files, attempts, checks, history):
    manifest_path = str(Path(repo.lockfile).with_name("package.json"))
    manifest = json.loads(files[manifest_path])
    lock_entries = json.loads(files[repo.lockfile])["packages"]
    old = {dep.path: dep.version for dep in inventory.dependencies}
    new = {path: entry.get("version") for path, entry in lock_entries.items() if path}
    changes = [{"path": path, "before": old.get(path), "after": new.get(path)}
               for path in sorted(old.keys() | new.keys()) if old.get(path) != new.get(path)]
    return agents.run("fix-inspection", finding, refs,
        version=attempts[-1].version, dependency_chain=chains(inventory, finding),
        manifest_entries={group: manifest[group][finding.package] for group in
            ("dependencies", "devDependencies", "optionalDependencies", "overrides")
            if finding.package in manifest.get(group, {})},
        lock_changes=changes, change_digest=evidence_digest(files), checks=checks, attempts=history)


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
    parser.add_argument("--all", action="store_true", dest="all_findings",
                        help="Remediate every current finding with its own draft PR")
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
    findings = reconcile(root, inventory, findings, store, agents, github, write=args.command != "remediate")
    states = store.all("state:" + scope)
    summary["states"] = {key: state["status"] for key, state in states.items()}
    summary["queue"] = [{"finding_id": item.finding_id, "package": item.package,
                         "installed_version": item.installed_version, "fixable": bool(candidates(item)),
                         "eligible": bool(candidates(item)) and states[item.finding_id]["status"] not in (
                             "remediation-in-progress", "risk-accepted")
                         and states[item.finding_id].get("attempted_revision") != sha}
                        for item in findings]
    every = args.command == "remediate" and getattr(args, "all_findings", False)
    if args.command in ("triage", "hunt", "validate", "remediate") and (args.finding_id or every):
        if args.command == "remediate" and args.ref is None and read_inventory(
                root, repo, sha).dependencies != inventory.dependencies:
            raise ValueError("Remediation requires a committed lockfile matching the working tree")
        selected = findings
        if not every:
            selected = [item for item in findings if item.finding_id == args.finding_id]
            if not selected:
                raise ValueError("Finding is absent from the current scan")
        finding = selected[0]
        state = states[finding.finding_id]
        refs = evidence(root, finding.package, **options_for(inventory, finding))
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
            def remediate_finding(finding):
                state = store.all("state:" + scope)[finding.finding_id]
                refs = evidence(root, finding.package, **options_for(inventory, finding))
                assessment = state["display"].get("assessment")
                result = {"finding_id": finding.finding_id, "package": finding.package,
                          "installed_version": finding.installed_version}
                if state["status"] in ("remediation-in-progress", "risk-accepted") or state.get("attempted_revision") == sha:
                    return {**result, "status": state["status"], "skipped": True}
                issue_number = store.get("issue", finding.finding_id)
                if github and issue_number is None:
                    raise ValueError("Run reconciliation before remediation so the finding has an issue")
                advice = agents.run("remediation", finding, refs, assessment=assessment,
                                    candidates=candidates(finding))
                files = {}
                attempts = []
                if candidates(finding) and advice is None:
                    result["escalation"] = "Remediation agent inspection unavailable"
                elif not candidates(finding) or advice.recommendation != "upgrade":
                    result["escalation"] = "No approved compatible upgrade candidate"
                else:
                    proposal = agents.run("test-development", finding, refs, assessment=assessment)
                    if proposal:
                        result["test_proposal"] = proposal.model_dump()
                    attempts, files = remediate(root, repo, inventory, findings, finding, config, scanner)
                    result["attempts"] = [item.model_dump() for item in attempts]
                    store.put("attempts", finding.finding_id, result["attempts"])
                    if not files:
                        result["escalation"] = "No candidate passed independent verification"
                from .pr_body import describe
                digest = []
                recorded_checks = attempts[-1].validation.checks if attempts else []
                for index, check in enumerate(recorded_checks):
                    label, passed, detail = describe(check)
                    if index == len(recorded_checks) - 1 and attempts[-1].validation.result != "pass":
                        passed = False
                    digest.append({"check": label, "passed": passed, "counts": detail,
                                   **({} if passed else {"failure_tail": check[-700:]})})
                history = [{"version": item.version, "result": item.validation.result} for item in attempts]
                if attempts:
                    review = agents.run("test-review", finding, refs, assessment=assessment,
                                        proposal=result.get("test_proposal"), version=attempts[-1].version,
                                        outcome=attempts[-1].validation.result, attempts=history,
                                        checks=digest)
                    if review:
                        result["test_review"] = review.model_dump()
                if files:
                    inspection = inspect_fix(agents, repo, inventory, finding, refs, files, attempts, digest, history)
                    if inspection:
                        result["fix_inspection"] = inspection.model_dump()
                        store.put("fix-inspection", finding.finding_id, result["fix_inspection"])
                    if inspection is None or inspection.recommendation != "upgrade":
                        result["escalation"] = ("Fix inspection unavailable" if inspection is None
                                                else "Fix inspector requested human review")
                        files = {}
                if not files and github:
                    issue = github.call("GET", f"/issues/{issue_number}")
                    state = {**state, "status": "needs-human-review", "reason": result["escalation"],
                             "attempted_revision": None if "unavailable" in result["escalation"] else sha,
                             "display": {**state["display"], "remediation_attempts": result.get("attempts", []),
                                         "test_review": result.get("test_review"), "fix_inspection": result.get("fix_inspection")}}
                    github.sync(issue, issue_payload(finding, state))
                    store.put("state:" + scope, finding.finding_id, state)
                if files:
                    story = agents.run("pr", finding, refs, assessment=assessment, advice=advice.model_dump() if advice else None,
                                       version=attempts[-1].version, attempts=history, checks=digest)
                    narrative = story.model_dump() if story else {"exposure": None, "residual_risks": "Human review required"}
                    result["draft"] = {"files": sorted(files), "validation": attempts[-1].model_dump(),
                                       "narrative": narrative}
                    if github:
                        issue = github.call("GET", f"/issues/{issue_number}")
                        extra = {"fix_inspection": result["fix_inspection"], "chains": chains(inventory, finding), "advice": advice.model_dump() if advice else None,
                                 "proposal": result.get("test_proposal"), "test_review": result.get("test_review")}
                        pull = github.draft(repo, issue, finding, files, attempts[-1], narrative,
                                            refs=refs, attempts=attempts, extra=extra)
                        store.put("pull", finding.finding_id, pull)
                        state = {**state, "status": "remediation-in-progress", "pull": pull.number,
                                 "reason": "Draft remediation PR exists"}
                        store.put("state:" + scope, finding.finding_id, state)
                        github.sync(issue, issue_payload(finding, state, validation=attempts[-1].model_dump()))
                        result["pull"] = pull.model_dump()
                return result

            if not every:
                result = remediate_finding(finding)
                if result.get("skipped"):
                    emit({"finding_id": finding.finding_id, "status": result["status"]})
                    return 0
                summary.update(result)
            else:
                summary["remediations"] = []
                for finding in selected:
                    try:
                        summary["remediations"].append(remediate_finding(finding))
                    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                        summary["remediations"].append({"finding_id": finding.finding_id, "package": finding.package,
                                                        "error": type(error).__name__})
    elif args.command == "remediate":
        raise ValueError("Remediation requires --finding-id or --all")
    summary["states"] = {key: state["status"] for key, state in store.all("state:" + scope).items()}
    summary["openai_calls"] = config.agent_calls - agents.remaining
    summary["metrics"] = store.agent_metrics()
    store.put("run", scope, summary)
    emit(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
