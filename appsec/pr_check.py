"""Verify remediation PR data against the trusted base without executing PR code."""
import argparse
import json
import re
import subprocess
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

from .cli import read_inventory, revision
from .config import load
from .models import Repository
from .osv import OSV
from .remediation import acceptable, revised_manifest, run_npm, validate_fix


def verify(pr, config, root, scanner, run):
    branch = re.fullmatch(r"appsec/([a-f0-9]{32})/([a-f0-9]{12})", pr["head"]["ref"])
    if (not branch or pr["head"]["repo"]["full_name"] != pr["base"]["repo"]["full_name"]
            or pr["state"] != "open"):
        raise ValueError("Expected an open same-repository AppSec remediation PR")
    sha = revision(root, "FETCH_HEAD")
    if sha != pr["head"]["sha"]:
        raise ValueError("PR head moved during validation")
    base = revision(root, pr["base"]["sha"])
    if base != revision(root, "HEAD") or base[:12] != branch[2]:
        raise ValueError("Remediation PR must target the checked-out default revision")
    lock = Path(config.lockfile)
    manifest = lock.with_name("package.json")
    changed = subprocess.check_output(
        ["git", "diff", "--no-renames", "--name-only", "-z", base, sha], cwd=root, timeout=30
    ).decode().split("\0")
    if set(filter(None, changed)) != {str(lock), str(manifest)}:
        raise ValueError("PR must change only its approved dependency files")
    repository = Repository(slug=pr["base"]["repo"]["full_name"], lockfile=str(lock), revision=base)
    inventory = read_inventory(root, repository, base)
    findings = scanner.scan(inventory)
    finding = next((item for item in findings if item.finding_id == branch[1]), None)
    if finding is None:
        raise ValueError("Could not identify the original finding on the base revision")
    for path in (lock, manifest):
        entry = subprocess.check_output(["git", "ls-tree", sha, "--", str(path)], cwd=root, timeout=15)
        if not entry.startswith(b"100644 blob "):
            raise ValueError("Expected regular manifest and lockfile blobs")
    archive = subprocess.check_output(["git", "archive", base], cwd=root, timeout=30)
    with tempfile.TemporaryDirectory(prefix="appsec-pr-check-") as directory:
        root_copy = Path(directory)
        with tarfile.open(fileobj=BytesIO(archive)) as tar:
            tar.extractall(root_copy, filter="data")
        original = json.loads((root_copy / manifest).read_text())
        candidate = subprocess.check_output(["git", "show", f"{sha}:{manifest}"], cwd=root, timeout=15)
        proposed = json.loads(candidate)
        version = next((value for group in ("dependencies", "devDependencies", "optionalDependencies", "overrides")
                        if isinstance(value := proposed.get(group, {}).get(finding.package), str)), None)
        if (version is None or not acceptable(finding.installed_version, version)
                or proposed != revised_manifest(original, finding, version)):
            raise ValueError("Manifest changes differ from the approved dependency operation")
        (root_copy / manifest).write_bytes(candidate)
        (root_copy / lock).write_bytes(subprocess.check_output(
            ["git", "show", f"{sha}:{lock}"], cwd=root, timeout=30))
        return validate_fix(root_copy, repository, findings, finding, scanner, run, config)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.pr.read_text()), load(args.config), Path.cwd(), OSV(), run_npm)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"result": "inconclusive", "error": type(error).__name__}))
        return 1
    print(result.model_dump_json(indent=2))
    return int(result.result != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
