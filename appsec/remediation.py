import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from .inventory import EXACT, PACKAGE, collect, requirements
from .models import Attempt, Validation

def version_key(version):
    return tuple(map(int, version.split(".")))


def candidates(finding):
    def stable(value):
        return EXACT.fullmatch(value) and "-" not in value and "+" not in value

    if not stable(finding.installed_version):
        return []
    original = version_key(finding.installed_version)
    return sorted({version for version in finding.fix_versions if stable(version)
                   and version_key(version) > original and version_key(version)[0] == original[0]},
                  key=version_key)


def run_npm(directory, args, *, network=False):
    name = f"appsec-npm-{uuid4().hex}"
    with tempfile.TemporaryFile() as log:
        try:
            completed = subprocess.run([
                "docker", "run", "--rm", "--name", name, "--network", "bridge" if network else "none",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
                "--memory=2g", "--cpus=2", "--user", f"{os.getuid()}:{os.getgid()}",
                "--volume", f"{directory}:/workspace", "--workdir", "/workspace",
                "--env", "HOME=/tmp", "--env", "NPM_CONFIG_USERCONFIG=/dev/null",
                "node:24", "npm", *args,
            ], stdout=log, stderr=subprocess.STDOUT, timeout=300, check=False)
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["docker", "rm", "--force", name], check=False, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return False, f"npm {args[0]} timed out"
        except OSError:
            return False, f"npm {args[0]} unavailable"
        log.seek(0)
        checksum = hashlib.file_digest(log, "sha256").hexdigest()
        log.seek(0, 2)
        size = log.tell()
        log.seek(max(0, size - 6000))
        output = log.read().decode(errors="replace")
        from .exposure import SECRET
        output = "\n".join(line for line in output.splitlines() if not SECRET.search(line))
        command = "npm " + " ".join(args)
        return completed.returncode == 0, (
            f"{command} exited {completed.returncode}. Output SHA-256 {checksum}\n"
            f"Final {min(size, 6000)} output bytes (sensitive lines omitted)\n{output}")


def approved_graph(inventory):
    return all(dep.registry.source == "public-npm" for dep in inventory.dependencies)


def validate_fix(directory, repository, before, finding, scanner, run, tests_enabled):
    inventory = collect(directory / repository.lockfile, repository)
    if not approved_graph(inventory):
        return Validation(result="fail", checks=["Updated graph contains an unsupported dependency source"])
    if any(dep.name == finding.package and dep.version == finding.installed_version
           for dep in inventory.dependencies):
        return Validation(result="fail", checks=["Original vulnerable version remains installed"])
    if not any(dep.name == finding.package for dep in inventory.dependencies):
        return Validation(result="fail", checks=["Target package disappeared during upgrade"])
    try:
        after = scanner.scan(inventory)
    except (RuntimeError, ValueError, KeyError):
        return Validation(result="inconclusive", checks=["Updated graph could not be scanned completely"])
    aliases = set(finding.advisory_ids)
    if any(item.package == finding.package and aliases.intersection(item.advisory_ids) for item in after):
        return Validation(result="fail", checks=["OSV still reports the original advisory"])
    if {item.finding_id for item in after} - {item.finding_id for item in before}:
        return Validation(result="fail", checks=["OSV reports new findings in the updated graph"])
    checks = ["Original version absent", "Original advisory absent and no new OSV findings"]
    if not tests_enabled:
        return Validation(result="inconclusive", checks=[*checks, "Reviewed npm test execution is disabled"])
    manifest_dir = (directory / repository.lockfile).parent
    ok, message = run(manifest_dir, ["ci", "--package-lock=true", "--ignore-scripts", "--no-audit", "--no-fund",
                                      "--registry=https://registry.npmjs.org"], network=True)
    checks.append(message)
    if ok:
        ok, message = run(manifest_dir, ["test", "--ignore-scripts"])
        checks.append(message)
    return Validation(result="pass" if ok else "fail", checks=checks)


def revised_manifest(manifest, finding, target):
    result = json.loads(json.dumps(manifest))
    locations = [group for group in ("dependencies", "devDependencies", "optionalDependencies")
                 if finding.package in result.get(group, {})]
    if locations:
        for group in locations:
            result[group][finding.package] = target
    else:
        if finding.package in result.get("peerDependencies", {}):
            raise ValueError("Peer dependencies require manual review")
        overrides = result.setdefault("overrides", {})
        if finding.package in overrides:
            raise ValueError("Existing override requires manual review")
        overrides[finding.package] = target
    return result


def remediate(root, repository, inventory, findings, finding, config, scanner, run=run_npm):
    if not approved_graph(inventory) or not PACKAGE.fullmatch(finding.package):
        return [], {}
    archive = subprocess.check_output(["git", "archive", repository.revision], cwd=root, timeout=30)
    attempts = []
    lock_path = Path(repository.lockfile)
    manifest_path = lock_path.with_name("package.json")
    for version in candidates(finding)[:config.remediation_attempts]:
        with tempfile.TemporaryDirectory(prefix="appsec-fix-") as temporary:
            directory = Path(temporary).resolve()
            with tarfile.open(fileobj=BytesIO(archive)) as tar:
                tar.extractall(directory, filter="data")
            manifest_file = directory / manifest_path
            lock = directory / lock_path
            if not manifest_file.is_file() or not lock.is_file() or manifest_file.is_symlink() or lock.is_symlink():
                return attempts, {}
            scoped = manifest_file.parent
            npm_config = scoped / ".npmrc"
            if not scoped.resolve().is_relative_to(directory):
                return attempts, {}
            if npm_config.is_symlink() or (npm_config.exists() and
                    npm_config.read_text().strip() not in {"", "legacy-peer-deps=true", "package-lock=false"}):
                return attempts, {}
            manifest = json.loads(manifest_file.read_text())
            if manifest.get("workspaces") or any(
                spec.startswith(("npm:", "file:", "git", "http", "workspace:", "link:"))
                for spec in requirements(manifest).values()
            ):
                return attempts, {}
            try:
                manifest = revised_manifest(manifest, finding, version)
            except ValueError:
                return attempts, {}
            manifest_file.write_text(json.dumps(manifest, indent=2) + "\n")
            ok, message = run(scoped, ["install", "--package-lock=true", "--package-lock-only", "--ignore-scripts", "--no-audit",
                                       "--no-fund", "--registry=https://registry.npmjs.org"], network=True)
            if ok:
                validation = validate_fix(directory, repository, findings, finding, scanner, run, config.run_npm_tests)
                validation = Validation(result=validation.result, checks=[message, *validation.checks])
            else:
                validation = Validation(result="fail", checks=[message])
            attempts.append(Attempt(version=version, validation=validation))
            if validation.result == "pass":
                return attempts, {str(manifest_path): manifest_file.read_text(), str(lock_path): lock.read_text()}
            if validation.result == "inconclusive":
                break
    return attempts, {}
