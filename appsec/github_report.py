"""Human-readable GitHub summaries. The audit export remains available for replay."""
import argparse
import html
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import quote


def text(value):
    # External advisory and model text must stay literal in Markdown tables and details.
    escaped = html.escape(str(value)).replace("\n", " ").replace("\r", " ")
    return re.sub(r"[\\|`*_~\[\]@#!]", lambda m: f"&#{ord(m[0])};", escaped)


def advisory_links(ids):
    return ", ".join(f"[{text(key)}](https://osv.dev/vulnerability/{quote(key, safe='')})" for key in ids)


def counts(values):
    return ", ".join(f"{count:,} {text(label)}" for label, count in Counter(values).most_common()) or "None"


def details(label, lines):
    return [f"<details><summary>{label}</summary>", "", *lines, "", "</details>", ""]


def reconciliation(directory, mode):
    def read(path):
        return json.loads(path.read_text())

    inventory = read(directory / "inventory.json")
    repository = inventory["repository"]
    sha = repository["revision"]
    base = f"https://github.com/{repository['slug']}"
    lock = f"{base}/blob/{sha}/{quote(repository['lockfile'])}"
    findings = [read(path) for path in sorted((directory / "findings").glob("*.json"))]
    findings.sort(key=lambda f: (not bool(f["agent_calls"]), f["state"]["package"], f["finding_id"]))
    calls = {f"calls/{p.name}": read(p) for p in sorted((directory / "calls").glob("*.json"))}
    deps = inventory["dependencies"]
    queries = read(directory / "scan-inputs.json")
    changes = read(directory / "changes.json")
    stages = Counter(v["execution"]["role"] for v in calls.values())
    accepted = sum(v["accepted_output"] is not None for v in calls.values())
    deferred = sum(any(d["reason"] == "Run request budget exhausted" and d["role"] == "triage"
                       for d in f["agent_decisions"]) for f in findings)
    states = counts(f["state"]["status"].replace("-", " ") for f in findings)
    validations = sum(f["exposure_validation"] is not None for f in findings)
    total = len(queries)
    issues = sum(f["issue_number"] is not None for f in findings)
    skipped = sum(d["registry"]["source"] != "public-npm" for d in deps)
    lines = ["# Dependency security report", "",
             f"**{len(findings)} tracked findings** · {states}.", "",
             f"Scanned [commit {sha[:12]}]({base}/commit/{sha}) in **{mode}** mode. "
             f"OpenAI returned {accepted} accepted assessments across {len(calls)} calls. "
             f"{deferred} findings waited for triage because the request budget was exhausted.", "",
             "## What ran", "", "| Stage | Input | Result |", "|---|---|---|",
             f"| Inventory | [npm lockfile]({lock}) | {len(deps):,} installed paths. Diff: {counts(changes.values())}. |",
             f"| OSV lookup | {total:,} distinct public npm package/version pairs | "
             f"{skipped} paths outside coverage. Exact versions and advisory links appear below. |",
             f"| Source investigation | Advisory matches and repository references | "
             f"{stages['triage']} triage calls and {stages['hunt']} hunt calls. "
             f"{len(calls) - accepted} calls produced no accepted decision. |",
             f"| Exposure validation | Investigation evidence | {validations} validation records. "
             "Behavioral reproduction requires separate evidence. |",
             f"| Finding management | Advisory facts and assessments | {states}. "
             + ("Issue synchronization skipped in dry-run mode. |" if mode == "dry-run"
                else f"{issues} issue identities recorded. |"),
             "| Dependency edits, compatibility tests and draft PR | Separate remediation workflow | "
             "Skipped during this reconciliation. |", "",
             "## Findings", "",
             "The table shows findings marked ready for remediation. A passing fix requires a separate validation run.", ""]
    ready = [f for f in findings if f["state"]["status"] == "remediation-ready"]
    if ready:
        lines += ["| Dependency | Advisory | OSV fix versions |", "|---|---|---|"]
        for f in ready:
            state = f["state"]
            fixes = (f["normalized_finding"] or {}).get("fix_versions", [])
            lines.append(f"| {text(state['package'])}@{text(state['version'])} | {advisory_links(state['aliases'])} | "
                         f"{', '.join(map(text, fixes)) or 'None recorded'} |")
        lines.append("")
    lines += ["### All finding decisions", "",
              "Expand a row to check its dependency paths, agent reasoning, rejection or deferral reason, and source citations.", ""]
    for f in findings:
        state = f["state"]
        fact = f["normalized_finding"] or {}
        title = f"{text(state['package'])}@{text(state['version'])} · {text(state['status'])} · {text(state['aliases'][0])}"
        body = [f"**Advisories**  {advisory_links(state['aliases'])}", "",
                f"**Installed paths**  {', '.join(text(p) for p in state['paths']) or 'Removed'}", "",
                f"**OSV fix versions**  {', '.join(text(v) for v in fact.get('fix_versions', [])) or 'None recorded'}", ""]
        if f["issue_number"]:
            body += [f"[Tracking issue #{int(f['issue_number'])}]({base}/issues/{int(f['issue_number'])})", ""]
        for filename in f["agent_calls"]:
            call = calls[filename]
            result = call["accepted_output"]
            body += [f"**{text(call['execution']['role'].capitalize())} · {text(call['execution']['model'])}**", "",
                     f"Input: {len(call['source_evidence'])} source references and the advisory facts above.", ""]
            if result:
                for field, value in result.items():
                    if field != "evidence_ids":
                        body.append(f"- **{text(field.replace('_', ' ').capitalize())}** — {text(value)}")
                body.append("")
                for ref in call["source_evidence"]:
                    if ref["id"] in result["evidence_ids"]:
                        url = f"{base}/blob/{sha}/{quote(ref['path'])}#L{int(ref['line'])}"
                        body.append(f"- [{text(ref['id'])} · {text(ref['path'])} line {ref['line']}]({url})")
            else:
                body.append(f"**Rejected output** — {text(call['decision'])}.")
            body.append("")
        for decision in f["agent_decisions"]:
            if decision["reason"] not in {calls[p]["decision"] for p in f["agent_calls"]}:
                body += [f"**{text(decision['role'].capitalize())}** — {text(decision['reason'])}.", ""]
        if not f["agent_calls"] and not f["agent_decisions"]:
            body += ["No call or deferral reason was recorded for this finding in this run.", ""]
        if validation := f["exposure_validation"]:
            body += [f"**Exposure validation** — {text(validation['result'])}.", "",
                     *[f"- {text(check)}" for check in validation["checks"]], ""]
        body += [f"Finding ID `{f['finding_id']}`."]
        lines.extend(details(title, body))
    # Inventory details are searchable and grouped by package/version on GitHub.
    lines.extend(details(f"Scanned packages and versions ({len(queries):,})",
                         ["| Package | Version |", "|---|---|",
                          *[f"| {text(q['name'])} | {text(q['version'])} |" for q in queries]]))
    return "\n".join(lines).rstrip() + "\n"


def checks(result):
    return [f"**Result** — {text(result.get('result', 'inconclusive'))}", "",
            *[f"- {text(check)}" for check in result.get("checks", [])],
            *([f"- {text(result['error'])}"] if result.get("error") else [])]


def workflow_summary(kind, data, selected=None):
    if kind == "validation":
        return "\n".join(["# Remediation PR verification", "", *checks(data)])
    if kind == "scan":
        lines = ["# Pull request dependency scan", "",
                 f"**{data['dependencies']:,} installed paths · {len(data['findings'])} advisory matches.**", "",
                 f"Changes against the base revision: {counts(data['changes'].values())}. "
                 f"{len(data['coverage_gaps'])} paths outside OSV coverage.", "",
                 "| Installed package | Advisory | Fixed versions |", "|---|---|---|"]
        for f in data["findings"]:
            lines.append(f"| {text(f['package'])}@{text(f['installed_version'])} | {advisory_links(f['advisory_ids'])} | "
                         f"{', '.join(map(text, f['fix_versions'])) or 'None recorded'} |")
        return "\n".join(lines)
    lines = ["# Dependency remediation", "", f"Selected finding: {text(selected or data.get('finding_id', 'unknown'))}", ""]
    if data.get("status"):
        lines.append(f"Current lifecycle state: **{text(data['status'])}**. No new attempt was started.")
    for f in data.get("findings", []):
        if f["finding_id"] == selected:
            lines += [f"**Original dependency** — {text(f['package'])}@{text(f['installed_version'])}. "
                      f"{advisory_links(f['advisory_ids'])}", ""]
    if proposal := data.get("test_proposal"):
        lines += [f"Proposed compatibility check: {text(proposal['behavior'])}. "
                  f"Expected result: {text(proposal['expected_result'])}.", ""]
    for attempt in data.get("attempts", []):
        lines += [f"## Candidate {text(attempt['version'])}", "", *checks(attempt["validation"]), ""]
    if draft := data.get("draft"):
        lines += [f"Files changed: {', '.join(map(text, draft['files']))}.", ""]
    if data.get("escalation"):
        lines.append(f"**Human review needed** — {text(data['escalation'])}.")
    if pull := data.get("pull"):
        lines.append(f"Draft PR #{int(pull['number'])} is ready for human review.")
    return "\n".join(lines)


def publish_summary(markdown):
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        # GitHub enforces a 1 MiB per-step summary limit.
        if len(markdown.encode()) > 1_000_000:
            markdown = markdown.split("## Findings", 1)[0][:5000] + "\n\nComplete report in the workflow artifact."
        with open(path, "a") as stream:
            print(markdown, file=stream)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("scan", "remediation", "validation"))
    parser.add_argument("input", type=Path)
    parser.add_argument("--finding-id")
    args = parser.parse_args()
    if args.input.is_file() and args.input.stat().st_size:
        report = workflow_summary(args.kind, json.loads(args.input.read_text()), args.finding_id)
    else:
        report = f"# {args.kind.capitalize()}\n\nThe job stopped before it recorded a result. See the failed step in this job."
    publish_summary(report)
