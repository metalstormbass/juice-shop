"""Publish the exact files that passed the isolated major-upgrade workflow."""
import json
import os
import subprocess
from pathlib import Path

from .github import GitHub
from .models import Attempt, Evidence, Finding, Repository
from .remediation import revised_manifest
from .store import SQLiteStore, digest


def main():
    summary = json.loads(Path("summary.json").read_text())
    if not (draft := summary.get("draft")):
        print("No tested upgrade is available for publication")
        return
    slug = os.environ["GITHUB_REPOSITORY"]
    github = GitHub(slug, os.environ["GITHUB_TOKEN"])
    _, base = github.default_head()
    expected = subprocess.check_output(["git", "rev-parse", "HEAD~3"], text=True).strip()
    if base != expected:
        raise ValueError("Default branch changed since the tested checkout was prepared")
    store = SQLiteStore(Path("appsec.sqlite"))
    finding = Finding.model_validate(store.get("finding", summary["finding_id"]))
    attempts = [Attempt.model_validate(item) for item in summary["attempts"]]
    final = attempts[-1]
    allowed = {"crypto-js": "4.2.0", "@cyclonedx/cyclonedx-npm": "6.0.0"}
    if final.validation.result != "pass" or allowed.get(finding.package) != final.version:
        raise ValueError("Update is outside the approved two-package trial")
    files = {name: (Path("tested-update") / name).read_text()
             for name in ("package.json", "package-lock.json")}
    if any(Path(name).read_bytes() != subprocess.check_output(["git", "show", f"{base}:{name}"])
           for name in files):
        raise ValueError("Tested baseline differs from the default branch")
    original = json.loads(Path("package.json").read_text())
    if revised_manifest(original, finding, final.version) != json.loads(files["package.json"]):
        raise ValueError("Manifest changes exceed the requested dependency update")
    extra = draft["review_context"]
    inspection = extra["fix_inspection"]
    with store.connect() as db:
        row = db.execute("select value from audit where namespace='agent-execution' and key='fix-inspection' "
                         "order by id desc limit 1").fetchone()
    call = json.loads(row[0])
    inputs = store.get("agent-inputs", call["input_digest"])
    output = store.get("agent-results", f"fix-inspection:{call['model']}:{call['input_digest']}")
    if (call["outcome"] != "completed" or output != inspection or inspection["recommendation"] != "upgrade"
            or inputs["context"]["change_digest"] != digest(files)):
        raise ValueError("Final agent inspection does not match the tested files")
    issue = next(issue for issue, state in github.issues() if state["id"] == finding.finding_id)
    refs = [Evidence.model_validate(ref) for ref in draft["refs"]]
    repository = Repository(slug=slug, lockfile="package-lock.json", revision=base)
    run_url = f"https://github.com/{slug}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    result = github.draft(repository, issue, finding, files, final, draft["narrative"],
                          refs=refs, attempts=attempts, extra={**extra, "run_url": run_url})
    print(result.url)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
        print(f"\n[Draft PR #{result.number}]({result.url})", file=stream)


if __name__ == "__main__":
    main()
