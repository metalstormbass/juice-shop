"""Four-part pull request description: finding, exposure, fix rationale and testing."""
import re
from urllib.parse import quote

from .github_report import advisory_links, text
from .github import protected

LABELS = (
    ("npm install", "Lockfile regenerated for the new version"),
    ("npm ci", "Clean install from the new lockfile"),
    ("npm rebuild", "Native package rebuilt"),
    ("npm run test:server", "Server unit tests"),
    ("npm exec -- tsc --noEmit", "TypeScript compile check"),
    ("npm test", "Project tests"),
)


def describe(check):
    """Turn one recorded check into a (label, passed, detail) row."""
    first = check.splitlines()[0] if check else ""
    match = re.match(r"(npm .*?) exited (\d+)\.", first)
    if not match:
        return text(first), True, ""
    command, code = match[1], int(match[2])
    label = next((name for prefix, name in LABELS if command.startswith(prefix)), text(command))
    if command.startswith("npm rebuild"):
        label += " " + command.split()[2]
    detail = ""
    counts = {key: re.search(rf"^(?:#|ℹ) {key} (\d+)", check, re.M) for key in ("tests", "pass", "fail", "skipped")}
    if counts["tests"] and counts["pass"] and counts["fail"]:
        detail = f"{counts['pass'][1]} passed, {counts['fail'][1]} failed"
        if counts["skipped"] and counts["skipped"][1] != "0":
            detail += f", {counts['skipped'][1]} skipped"
    return label, code == 0, detail


def source_links(repository, refs, ids):
    base = f"https://github.com/{repository.slug}/blob/{repository.revision}/"
    by_id = {ref.id: ref for ref in refs}
    return [f"[`{ref.path.replace('`', '')}` line {ref.line}]({base}{quote(ref.path)}#L{ref.line})"
            for ref in (by_id[i] for i in ids if i in by_id)]


def usage_lines(repository, finding, refs, chains):
    """Deterministic account of where the package is declared and called in this repository."""
    base = f"https://github.com/{repository.slug}/blob/{repository.revision}/"

    def item(ref):
        code = ref.text.replace("`", "'")[:110]
        return f"- [`{ref.path.replace('`', '')}:{ref.line}`]({base}{quote(ref.path)}#L{ref.line}) — `{code}`"

    lines = []
    if chains:
        lines += ["**Dependency chain:** " + "; ".join(" → ".join(f"`{n}`" for n in chain) for chain in chains), ""]
    manifest = [r for r in refs if r.kind == "manifest"]
    lines += ["**Declared in `package.json`:**", *(map(item, manifest) if manifest else
              ["- Not declared directly; it is installed only as a transitive dependency."]), ""]
    calls = [r for r in refs if r.kind.startswith("project ") and ("call" in r.kind or "import" in r.kind)]
    lines += ["**Called from application code:**"]
    if calls:
        lines += [*map(item, calls[:8]), ""]
    else:
        names = ", ".join(sorted({c[0] for c in chains})) or finding.package
        lines += [f"- No import or call of `{text(finding.package)}`"
                  + (f" or of `{text(names)}`" if names != finding.package else "")
                  + " was found in application source (lexical search; dynamic loading is not detected).", ""]
    tests = [r for r in refs if r.kind.startswith("test ")]
    if tests:
        lines += ["**Used in tests:**", *map(item, tests[:4]), ""]
    return lines


def render(repository, issue, finding, attempt, attempts, narrative, refs, extra):
    review = extra.get("test_review") or {}
    advice = extra.get("advice") or {}
    summary = next((a.summary for a in finding.advisories if a.summary), "")
    lines = [f"Related issue #{issue['number']}. Human review required.", "",
             "## 1. The finding", "",
             f"**{text(finding.package)}** {text(finding.installed_version)} → **{text(attempt.version)}** "
             f"· severity {text(finding.severity)} · {advisory_links(finding.advisory_ids)}", ""]
    if summary:
        lines += [f"> {text(summary[:300])}", ""]
    lines += ["Installed at: " + ", ".join(f"`{p.replace('`', '')}`" for p in finding.dependency_paths[:5]), "",
              "## 2. Why it affects this code", "",
              text(narrative.get("exposure") or "Application use has not been established."), ""]
    lines += usage_lines(repository, finding, refs, extra.get("chains") or [])
    lines += ["## 3. Why this fix", "",
              text(narrative.get("rationale") or f"{attempt.version} is a same-major release OSV lists as fixed."), ""]
    if inspection := extra.get("fix_inspection"):
        lines += [f"**Agent inspection of tested version {text(attempt.version)}**", "",
                  text(inspection["reasoning"]), "",
                  "Compatibility risks: " + text(inspection["compatibility_risks"]), ""]
        links = source_links(repository, refs, inspection["evidence_ids"])
        if links:
            lines += ["Inspection evidence: " + " · ".join(links), ""]
    if advice.get("compatibility_risks") and len(attempts) == 1:
        lines += [f"Compatibility risk noted: {text(advice['compatibility_risks'])}", ""]
    if len(attempts) > 1:
        lines += ["Versions tried before this one:", ""]
        for earlier in attempts[:-1]:
            last = earlier.validation.checks[-1] if earlier.validation.checks else ""
            label, passed, _ = describe(last)
            reason = f"{label} failed" if last.startswith("npm ") and not passed else last
            lines.append(f"- {text(earlier.version)}: {text(earlier.validation.result)} — {text(reason[:200])}")
        lines.append("")
    lines += ["## 4. Testing", "", "| Check | Result |", "|---|---|"]
    for check in attempt.validation.checks:
        label, passed, detail = describe(check)
        lines.append(f"| {label} | {'✅' if passed else '❌'} {text(detail)} |")
    lines += ["", f"Verification outcome: **{text(attempt.validation.result)}**. "
              "The PR only changes `package.json` and `package-lock.json`.", ""]
    behavior = attempt.validation.security_behavior
    if behavior:
        lines += ["**Maintained security behavior checks**", ""]
        for result in behavior:
            lines += [f"- {'Pass' if result.passed else 'Fail'} — npm {text(' '.join(result.command))}"]
        lines.append("")
    else:
        lines += ["Focused security behavior tests were unavailable for this candidate.", ""]
    if verdict := extra.get("fix_validation"):
        lines += ["**Fix validation agent**", "", text(verdict["rationale"]), "",
                  f"Limits: {text(verdict['remaining_uncertainty'])}", ""]
    if review:
        lines += ["**AI test review**", "", text(review.get("summary", "")), "",
                  f"- **Behavior exercised:** {text(review.get('behavior_covered', ''))}",
                  f"- **Not covered by tests:** {text(review.get('untested_behavior', ''))}", ""]
        tests = source_links(repository, [r for r in refs if "test" in r.kind], review.get("evidence_ids", []))
        if tests:
            lines += ["Relevant tests: " + " · ".join(tests), ""]
    if proposal := extra.get("proposal"):
        lines += [f"Compatibility behavior to keep protected: {text(proposal['behavior'])} "
                  f"(expected: {text(proposal['expected_result'])}).", ""]
    if narrative.get("residual_risks"):
        lines += [f"**Remaining uncertainty:** {text(narrative['residual_risks'])}", ""]
    lines += ["<details><summary>Raw command output</summary>", ""]
    lines += [protected(check) + "\n" for check in attempt.validation.checks]
    lines += ["</details>"]
    return "\n".join(lines)
