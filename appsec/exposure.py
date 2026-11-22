"""Bounded static evidence for dependency exposure review."""
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

from .models import Evidence

SECRET = re.compile(r"(?i)secret|token|password|credential|private.key|api.key|authorization|bearer|sk-[a-z0-9]")
IDENT = r"[A-Za-z_$][\w$]*"
INPUT_SOURCE = re.compile(r"\b(?:process\.argv|(?:req|request)\.(?:body|file|files|params|query|headers))\b")
SOURCE = (".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx")
ROOTS = ("lib/", "routes/", "models/", "src/", "test/", "tests/", "scripts/", "frontend/src/app/")


def advisory_context(details):
    prose = []
    for line in details.splitlines():
        if re.search(r"(?i)^\s*(?:#+\s*)?(?:proof.of.concept|reproduction|exploit example|poc\b)|^```", line):
            break
        if line.strip() and not SECRET.search(line) and not line.lstrip().startswith(("<", "http")):
            prose.append(line.strip())
    return " ".join(prose)[:1800]


def graph_context(inventory, finding):
    paths = set(finding.dependency_paths)
    installed = [d for d in inventory.dependencies if d.path in paths]
    parents = sorted({d.path for d in inventory.dependencies if paths.intersection(d.edges.values())})
    return {"lockfile": inventory.repository.lockfile,
            "installed": [{"path": d.path, "type": d.type, "direct": d.direct} for d in installed[:16]],
            "parent_packages": parents[:12], "parent_count": len(parents)}


def chains(inventory, finding, depth=8):
    """Dependency chains from a direct dependency to each installed copy, e.g. express-jwt -> moment."""
    by_path = {d.path: d for d in inventory.dependencies}
    parents = {}
    for dep in inventory.dependencies:
        for target in dep.edges.values():
            parents.setdefault(target, []).append(dep.path)
    result = []
    for start in finding.dependency_paths:
        frontier = [[start]]
        for _ in range(depth):
            frontier = [[parent, *chain] if not by_path[chain[0]].direct else chain
                        for chain in frontier for parent in (parents.get(chain[0], [None])
                                                             if not by_path[chain[0]].direct else [None])]
            frontier = [chain for chain in frontier if None not in chain]
            if all(by_path[chain[0]].direct for chain in frontier):
                break
        for chain in frontier[:3]:
            names = [by_path[path].name for path in chain]
            if by_path[chain[0]].direct and names not in result:
                result.append(names)
    return result[:4]


def options_for(inventory, finding):
    aliases = [path.rsplit("node_modules/", 1)[-1] for path in finding.dependency_paths]
    paths = set(finding.dependency_paths)
    installed = [d for d in inventory.dependencies if d.path in paths]
    via = sorted({chain[0] for chain in chains(inventory, finding)} - {finding.package, *aliases})
    return {"lockfile": inventory.repository.lockfile, "aliases": aliases, "via": via,
            "dev_only": bool(installed) and all(d.type != "production" for d in installed)}


def references(root, package, *, limit=16, lockfile="package-lock.json", aliases=(), via=(), dev_only=False):
    project = Path(lockfile).parent

    def matcher(names):
        spec = rf"""['"](?:{"|".join(re.escape(n) for n in sorted(names))})(?:/[^'"]+)?['"]"""
        return re.compile(rf"(?:\bfrom\s*|\bimport\s*|\b(?:require|import)\s*\(\s*){spec}")

    targets = [{"label": "", "names": {package, *aliases}, "imported": matcher({package, *aliases}), "symbols": set()}]
    targets += [{"label": f" of parent {name}", "names": {name}, "imported": matcher({name}), "symbols": set()}
                for name in via]
    bind = re.compile(rf"\bimport\s+(?:\*\s+as\s+)?({IDENT})\s+from|\b(?:const|let|var)\s+({IDENT})\s*=\s*require")
    declared = {package, *aliases, *via}
    rows = []
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root, timeout=15)
    for name in sorted(os.fsdecode(files).split("\0")):
        if not name or not Path(name).is_relative_to(project):
            continue
        relative = Path(name).relative_to(project).as_posix()
        build = relative == "Dockerfile"
        manifest = relative == "package.json"
        if not (build or manifest or (relative.endswith(SOURCE) and
                (relative.startswith(ROOTS) or "/" not in relative))):
            continue
        path = root / name
        if (SECRET.search(name) or path.is_symlink() or not path.is_file() or
                not path.resolve().is_relative_to(root) or path.stat().st_size > 250_000):
            continue
        lines = path.read_text(errors="replace").splitlines()
        test = relative.startswith(("tests/", "test/")) or ".spec." in name or ".test." in name
        scope = "test" if test else "project"
        # A nested project can resolve a different version from the selected lockfile.
        if any((parent / "package.json").is_file() for parent in path.parents
               if parent != root / project and parent.is_relative_to(root / project)):
            scope = "other project"
        for target in targets:
            target["symbols"] = set()
        for number, line in enumerate(lines, 1):
            sensitive = bool(SECRET.search(line))
            if line.lstrip().startswith(("//", "/*", "*")) or (sensitive and (build or manifest)):
                continue
            kind = None
            if build:
                # The Dockerfile only matters when it mentions the package or a production-only install hides a dev package.
                if package in line or (dev_only and re.match(r"^RUN npm (install|ci|dedupe).*--omit=dev", line)):
                    kind, rank, group = "build configuration", 3, "build"
            elif manifest:
                if any(re.search(rf'"{re.escape(name)}"\s*:', line) for name in declared):
                    kind, rank, group = "manifest", 1, "manifest"
            else:
                for target in targets:
                    suffix = target["label"]
                    if target["imported"].search(line) and not re.match(r"^\s*(?:export|import)\s+type\b", line):
                        kind, rank, group = f"{scope} import{suffix}", 1 + bool(suffix), f"import{suffix}"
                        if match := bind.search(line):
                            target["symbols"].add(next(s for s in match.groups() if s))
                        if named := re.search(r"\bimport\s*\{([^}]+)\}", line):
                            target["symbols"].update(s.strip().split(" as ")[-1] for s in named[1].split(",")
                                                     if re.fullmatch(IDENT + r"(?: as " + IDENT + ")?", s.strip()))
                        break
                    if any(re.search(rf"(?<![\w$]){re.escape(s)}\s*(?:\.\s*{IDENT}\s*)?\(", line)
                           for s in target["symbols"]):
                        kind, rank, group = f"{scope} call candidate{suffix}", int(bool(suffix)), f"call{suffix}"
                        if not suffix and scope == "project" and not sensitive and INPUT_SOURCE.search(line):
                            rows.append((0, name, number, "input origin at call", line.strip()[:300], "origin"))
                        break
                if kind is None and package in line:
                    kind, rank, group = "text mention", 5, "text"
            if kind is None:
                continue
            shown = "[line withheld: matches the sensitive-value filter]" if sensitive else line.strip()[:300]
            rows.append((rank + (2 if scope != "project" and not build and not manifest else 0),
                         name, number, kind, shown, f"{scope}:{group}"))
    selected = []
    by_group = Counter()
    for row in sorted(rows):
        group = row[5]
        if by_group[group] >= max(2, limit // 3):
            continue
        selected.append(row)
        by_group[group] += 1
        if len(selected) == limit:
            break
    return [Evidence(id=f"E{i}", path=name, line=number, kind=kind, text=line)
            for i, (_, name, number, kind, line, _) in enumerate(selected, 1)]
