import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .models import Dependency, Inventory, Registry, Repository

EXACT = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[\w.-]+)?(?:\+[\w.-]+)?", re.ASCII)
PACKAGE = re.compile(r"(?:@[a-zA-Z0-9_.-]+/)?[a-zA-Z0-9_][a-zA-Z0-9_.-]*")
GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def requirements(entry):
    return {name: spec for group in GROUPS for name, spec in entry.get(group, {}).items()}


def resolve(packages, parent, name):
    while True:
        candidate = f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not parent:
            return None
        parent = parent.rpartition("/node_modules/")[0]


def npm_registry(entry, name, version):
    url = urlsplit(entry.get("resolved") or "")
    source = "unsupported"
    if (EXACT.fullmatch(version) and not entry.get("link") and not entry.get("inBundle")
            and url.scheme == "https" and url.hostname and not url.username and not url.password
            and url.path.endswith(".tgz")):
        if url.hostname == "registry.npmjs.org":
            filename = name.rsplit("/", 1)[-1]
            expected = f"/{name}/-/{filename}-{version}.tgz"
            if (url.port in (None, 443) and unquote(url.path) == expected
                    and not url.query and not url.fragment):
                source = "public-npm"
        else:
            source = "other-registry"
    return Registry(host=url.hostname, source=source)


def collect(path: Path, repository: Repository) -> Inventory:
    if path.stat().st_size > 12_000_000:
        raise ValueError("Lockfile exceeds the supported size")
    lock = json.loads(path.read_text())
    if lock.get("lockfileVersion") not in (2, 3) or "" not in lock.get("packages", {}):
        raise ValueError("Expected an npm v2 or v3 lockfile with a root packages entry")
    packages = lock["packages"]
    declarations = {}
    for parent, entry in packages.items():
        for name, spec in requirements(entry).items():
            target = resolve(packages, parent, name)
            if target:
                declarations.setdefault(target, []).append(spec)
    deps = []
    for path, entry in sorted(packages.items()):
        if not path:
            continue
        install_name = path.rsplit("node_modules/", 1)[-1]
        aliases = {spec[4:].rsplit("@", 1)[0] for spec in declarations.get(path, [])
                   if spec.startswith("npm:")}
        name = entry.get("name") or (next(iter(aliases)) if len(aliases) == 1 else install_name)
        version = entry.get("version", "")
        registry = npm_registry(entry, name, version)
        install_chain = path.removeprefix("node_modules/").split("/node_modules/")
        if (not PACKAGE.fullmatch(name) or aliases.difference({name})
                or not path.startswith("node_modules/")
                or not all(PACKAGE.fullmatch(part) for part in install_chain)):
            registry = Registry(host=registry.host, source="unsupported")
        kind = next((kind for flag, kind in (("optional", "optional"), ("dev", "development"),
                                             ("peer", "peer")) if entry.get(flag)), "production")
        edges = {name: target for name in requirements(entry)
                 if (target := resolve(packages, path, name))}
        direct = path == f"node_modules/{install_name}" and install_name in requirements(packages[""])
        deps.append(Dependency(name=name, version=version, path=path, type=kind,
                               registry=registry, edges=edges, direct=direct))
    return Inventory(repository=repository, dependencies=deps)


def compare(previous, current):
    old = {item.path: item for item in previous.dependencies} if previous else {}
    new = {item.path: item for item in current.dependencies}
    changes = {}
    for path in sorted(old.keys() | new.keys()):
        if path not in old:
            change = "added"
        elif path not in new:
            change = "removed"
        elif old[path].version != new[path].version:
            change = "version changed"
        else:
            change = "unchanged" if old[path] == new[path] else "metadata changed"
        changes[path] = change
    return changes
