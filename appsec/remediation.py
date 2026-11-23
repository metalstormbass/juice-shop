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
from .models import AdvisoryComparison, Attempt, SecurityBehaviorResult, Validation

def version_key(version):
    return tuple(map(int, version.split(".")))


def stable(value):
    return EXACT.fullmatch(value) and "-" not in value and "+" not in value


def acceptable(installed, version):
    """A stable, newer release in the same major version as the installed one."""
    if not stable(installed) or not stable(version):
        return False
    return version_key(version) > version_key(installed) and version_key(version)[0] == version_key(installed)[0]


def candidates(finding):
    return sorted({version for version in finding.fix_versions if (finding.package, version) == ("crypto-js", "4.2.0")
                  or acceptable(finding.installed_version, version)},
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


PBKDF2_ADVISORY = "CVE-2023-46233"
PBKDF2_COMMAND = ["exec", "--", "node", "appsec/checks/crypto-js-pbkdf2.cjs"]


def validate_fix(directory, repository, before, finding, scanner, run, config, *, plan=None):
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
    known = {}
    for item in before:
        known.setdefault(item.package, set()).update(item.advisory_ids)
    # Advisories that already affected the package may remain until a later fix; only new ones are regressions.
    fresh = [item for item in after if not known.get(item.package, set()).intersection(item.advisory_ids)]
    remaining = {a for item in after if item.package == finding.package for a in item.advisory_ids}
    comparison = AdvisoryComparison(
        original_advisories=sorted(aliases), before_versions=sorted({item.installed_version for item in before
            if item.package == finding.package} | {finding.installed_version}),
        after_versions=sorted({dep.version for dep in inventory.dependencies if dep.name == finding.package}),
        remaining_advisories=sorted(remaining), original_advisories_remaining=sorted(aliases & remaining),
        new_advisories=sorted({a for item in fresh for a in item.advisory_ids}))
    if comparison.original_advisories_remaining:
        return Validation(result="fail", checks=["OSV still reports the original advisory"],
                          advisory_comparison=comparison)
    if fresh:
        retry = sorted({version for item in fresh if item.package == finding.package
                        for version in item.fix_versions if (finding.package, version) == ("crypto-js", "4.2.0")
                  or acceptable(finding.installed_version, version)},
                       key=version_key)
        return Validation(result="fail", retry_versions=retry[-1:], advisory_comparison=comparison,
                          checks=["OSV reports new advisories in the updated graph: "
                                  + ", ".join(sorted({a for item in fresh for a in item.advisory_ids}))])
    checks = ["Original version absent", "Original advisory absent and no new OSV advisories"]
    if not config.run_npm_tests:
        return Validation(result="inconclusive", checks=[*checks, "Reviewed npm test execution is disabled"],
                          advisory_comparison=comparison)
    manifest_dir = (directory / repository.lockfile).parent
    ok, message = run(manifest_dir, ["ci", "--package-lock=true", "--ignore-scripts", "--no-audit", "--no-fund",
                                      "--registry=https://registry.npmjs.org"], network=True)
    checks.append(message)
    for package in config.rebuild_packages if ok else []:
        ok, message = run(manifest_dir, ["rebuild", package, "--no-audit", "--no-fund",
                                          "--registry=https://registry.npmjs.org"], network=True)
        checks.append(message)
        if not ok:
            break
    if ok and config.prepare_frontend:
        ok, message = run(manifest_dir, ["install", "--prefix", "frontend", "--ignore-scripts",
                                          "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org"],
                          network=True)
        checks.append(message)
    for command in config.test_commands if ok else []:
        ok, message = run(manifest_dir, command)
        checks.append(message)
        if not ok:
            break
    behavior = []
    focused = [(None, command) for command in config.security_behavior_tests.get(finding.package, [])]
    for advisory in finding.advisory_ids:
        focused.extend((advisory, command) for command in config.advisory_behavior_tests.get(advisory, []))
    for advisory, command in focused if ok else []:
        fixture = None
        if advisory == PBKDF2_ADVISORY and command == PBKDF2_COMMAND:
            fixture = plan.fixture if plan else "ascii"
            command = [*command, fixture]
        ok, message = run(manifest_dir, command)
        behavior.append(SecurityBehaviorResult(advisory_id=advisory, fixture=fixture,
                                               command=command, passed=ok, evidence=message))
        checks.append(message)
        if not ok:
            break
    if ok and config.require_advisory_test and not any(result.advisory_id for result in behavior):
        return Validation(result="inconclusive",
                          checks=[*checks, "No maintained runtime assertion covers the original advisory"],
                          advisory_comparison=comparison, security_behavior=behavior)
    return Validation(result="pass" if ok else "fail", checks=checks,
                      advisory_comparison=comparison, security_behavior=behavior)


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


def remediate(root, repository, inventory, findings, finding, config, scanner, run=run_npm, *, plan=None):
    if not approved_graph(inventory) or not PACKAGE.fullmatch(finding.package):
        return [], {}
    archive = subprocess.check_output(["git", "archive", repository.revision], cwd=root, timeout=30)
    attempts = []
    lock_path = Path(repository.lockfile)
    manifest_path = lock_path.with_name("package.json")
    queue = candidates(finding)
    tried = set()
    while queue and len(attempts) < config.remediation_attempts:
        version = queue.pop(0)
        if version in tried:
            continue
        tried.add(version)
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
                validation = validate_fix(directory, repository, findings, finding, scanner, run, config, plan=plan)
                validation = validation.model_copy(update={"checks": [message, *validation.checks]})
            else:
                validation = Validation(result="fail", checks=[message])
            attempts.append(Attempt(version=version, validation=validation))
            # A newer release that clears the advisories introduced by this one is tried next.
            queue = [v for v in validation.retry_versions if v not in tried] + queue
            if validation.result == "pass":
                return attempts, {str(manifest_path): manifest_file.read_text(), str(lock_path): lock.read_text()}
            if validation.result == "inconclusive":
                break
    return attempts, {}
