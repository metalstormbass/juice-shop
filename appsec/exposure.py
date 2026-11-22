"""Bounded static evidence for dependency exposure review."""
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

from .models import Evidence

SECRET = re.compile(r"(?i)secret|token|password|credential|private.key|api.key|authorization|bearer|sk-[a-z0-9]")
IDENT = r"[A-Za-z_$][\w$]*"
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


def references(root, package, *, limit=16, lockfile="package-lock.json", aliases=()):
    project = Path(lockfile).parent
    names = "|".join(re.escape(n) for n in sorted({package, *aliases}))
    spec = rf"""['"](?:{names})(?:/[^'"]+)?['"]"""
    imported = re.compile(rf"(?:\bfrom\s*|\bimport\s*|\b(?:require|import)\s*\(\s*){spec}")
    bind = re.compile(rf"\bimport\s+(?:\*\s+as\s+)?({IDENT})\s+from|\b(?:const|let|var)\s+({IDENT})\s*=\s*require")
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
        symbols = set()
        for number, line in enumerate(lines, 1):
            if SECRET.search(line) or line.lstrip().startswith(("//", "/*", "*")):
                continue
            if build and (re.match(r"^FROM\s|^RUN npm (install|ci|dedupe).*--omit=dev", line) or package in line):
                kind, rank = "build configuration", 3
            elif manifest and package in line:
                kind, rank = "manifest", 4
            elif imported.search(line) and not re.match(r"^\s*(?:export|import)\s+type\b", line):
                kind, rank = f"{scope} import", 1
                if match := bind.search(line):
                    symbols.add(next(s for s in match.groups() if s))
                if named := re.search(r"\bimport\s*\{([^}]+)\}", line):
                    symbols.update(s.strip().split(" as ")[-1] for s in named[1].split(",")
                                   if re.fullmatch(IDENT + r"(?: as " + IDENT + ")?", s.strip()))
            elif any(re.search(rf"(?<![\w$]){re.escape(s)}\s*(?:\.\s*{IDENT}\s*)?\(", line) for s in symbols):
                kind, rank = f"{scope} call candidate", 0
            elif package in line:
                kind, rank = "text mention", 5
            else:
                continue
            rows.append((rank + (2 if scope != "project" and not build else 0), name, number, kind, line.strip()[:300]))
    selected = []
    by_kind = Counter()
    for row in sorted(rows):
        kind = row[3]
        if by_kind[kind] >= max(2, limit // 3):
            continue
        selected.append(row)
        by_kind[kind] += 1
        if len(selected) == limit:
            break
    return [Evidence(id=f"E{i}", path=name, line=number, kind=kind, text=line)
            for i, (_, name, number, kind, line) in enumerate(selected, 1)]
