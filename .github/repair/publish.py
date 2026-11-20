"""Create one PR per verified dependency update on the current default branch."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from verify import FILES, NAME, VERSION, read


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main(directory):
    summary = read(directory / "summary.json")
    base = os.environ["DEFAULT_BRANCH"]
    repo = os.environ["GITHUB_REPOSITORY"]
    if repo != "metalstormbass/juice-shop":
        raise ValueError("Repair PRs are restricted to the metalstormbass/juice-shop fork.")
    sha = run("git", "rev-parse", "HEAD")
    if sha != summary["base"] or run("git", "ls-remote", "origin", f"refs/heads/{base}").split()[0] != sha:
        raise ValueError("Default branch changed after validation.")
    for record in summary["verified"]:
        package, version = record["package"], record["version"]
        bundle = record["bundle"]
        if not NAME.fullmatch(package) or not VERSION.fullmatch(version) or not re.fullmatch(r"[0-9]+", bundle):
            raise ValueError("Invalid verified candidate.")
        branch = f"grype-repair/{package.replace('/', '-')}-{version}"
        if run("git", "ls-remote", "origin", f"refs/heads/{branch}"):
            print(f"Repair branch already exists for {package} {version}.")
            continue
        source = directory / bundle
        expected = read(Path(FILES[0]))
        expected["dependencies"][package] = version
        if expected != read(source / FILES[0]) or not record["removed"] or record["added_findings"] != 0:
            raise ValueError("Candidate manifest or scan evidence failed validation.")
        for name in FILES:
            if hashlib.sha256((source / name).read_bytes()).hexdigest() != record["hashes"][name]:
                raise ValueError("Artifact digest mismatch.")
        run("git", "switch", "--detach", sha)
        shutil.copyfile(source / FILES[0], FILES[0])
        run("git", "add", "--", FILES[0])
        run("git", "-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-m", f"Update {package} to {version}")
        run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
        body = (f"## Grype evidence\n\nRemoved advisories: {', '.join(record['removed'])}. "
                "The candidate introduced zero new findings.\n\n"
                f"## Agent decision\n\n{record['finding_rationale']}\n\n{record['fix_rationale']}\n\n"
                f"## Verification\n\n{record['tests']}. The resolved npm lockfile is retained in the run artifact.\n\n"
                f"[Workflow evidence](https://github.com/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']})\n")
        body_path = Path(os.environ["RUNNER_TEMP"]) / "repair-pr.md"
        body_path.write_text(body)
        print(run("gh", "pr", "create", "--repo", repo, "--base", base, "--head", branch,
                  "--title", f"Update {package} to {version}", "--body-file", str(body_path)))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
