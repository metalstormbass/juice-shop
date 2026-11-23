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
    flat = str(value).replace("\n", " ").replace("\r", " ")
    return re.sub(r"[&<>\"'\\|`*_~\[\]@#!]", lambda m: f"&#{ord(m[0])};", flat)


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
             "Local priority reflects the available application evidence. A passing fix requires a separate validation run.", ""]
    assessed = [(call["input"]["facts"], call["accepted_output"]) for call in calls.values()
                if call["accepted_output"] and call["accepted_output"].get("priority")]
    if assessed:
        lines += ["### Risk decisions", "",
                  "| Dependency | Advisory | Local priority | Why act or investigate |",
                  "|---|---|---|---|"]
        for facts, assessment in assessed:
            lines.append(f"| {text(facts['package'])}@{text(facts['installed_version'])} | "
                         f"{advisory_links(facts['advisory_ids'])} | {text(assessment['priority'])} | "
                         f"{text(assessment['priority_reason'])} |")
        lines.append("")
    ready = [f for f in findings if f["state"]["status"] == "remediation-ready"]
    if ready:
        lines += ["### Ready for remediation", "", "| Dependency | Advisory | OSV fix versions |", "|---|---|---|"]
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
                    if isinstance(value, dict) and "assessment" in value:
                        citations = ", ".join(value["evidence_ids"]) or "no source citation"
                        body.append(f"- **{text(field.replace('_', ' ').capitalize())} · {text(value['status'])}** "
                                    f"— {text(value['assessment'])} ({text(citations)})")
                    elif field == "missing_evidence":
                        body.append(f"- **Evidence still needed** — {text('; '.join(value) or 'None identified')}")
                    elif field != "evidence_ids":
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
    return remediation_summary(data, selected)


def remediation_summary(data, selected=None):
    from .pr_body import describe

    if "remediations" in data:
        return "\n\n".join(remediation_summary(item, item["finding_id"]) for item in data["remediations"])
    selected = selected or data.get("finding_id")
    finding = next((f for f in data.get("findings", []) if f["finding_id"] == selected), {})
    package = data.get("package", finding.get("package", "Selected dependency"))
    version = data.get("installed_version", finding.get("installed_version", "unknown"))
    attempts = data.get("attempts", [])
    pull = data.get("pull")
    lines = [f"# Remediation review · {text(package)}@{text(version)}", "",
             f"Finding ID `{text(selected or 'unavailable')}`.", "",
             "## 1. Inventory and advisory match", ""]
    if finding:
        lines += [f"- **Original advisory** — {advisory_links(finding['advisory_ids'])}",
                  f"- **Installed paths** — {', '.join(map(text, finding['dependency_paths']))}",
                  f"- **OSV fix versions** — {', '.join(map(text, finding['fix_versions'])) or 'None'}", ""]
    else:
        lines += ["Finding details are available in the reconciliation run.", ""]
    if data.get("skipped") or data.get("status") or data.get("error"):
        lines += [f"**Disposition** — {text(data.get('status') or data.get('error') or 'Skipped')}.", ""]
    lines += ["## 2. Exposure triage and candidate review", ""]
    if triage := data.get("triage"):
        lines += [f"- **Triage** — {text(triage['classification'])}. {text(triage['reasoning'])}"]
    if advice := data.get("remediation_advice"):
        lines += [f"- **Remediation agent** — {text(advice['recommendation'])}. {text(advice['reasoning'])}",
                  f"- **Compatibility risks** — {text(advice['compatibility_risks'])}"]
    else:
        lines += ["- **Remediation agent** — No decision recorded."]
    if proposal := data.get("test_proposal"):
        lines += [f"- **Test development agent** — {text(proposal['behavior'])}. "
                  f"Expected result: {text(proposal['expected_result'])}."]
    else:
        lines += ["- **Test development agent** — No proposal recorded."]
    lines += ["", "## 3. Upgrade, advisory rescan and compatibility checks", ""]
    if not attempts:
        lines += ["No candidate reached verification.", ""]
    for attempt in attempts:
        validation = attempt["validation"]
        lines += [f"### {text(attempt['version'])} · {text(validation['result'])}", ""]
        if comparison := validation.get("advisory_comparison"):
            lines += ["| Evidence | Result |", "| --- | --- |",
                      f"| Affected versions before → installed versions after | {', '.join(map(text, comparison['before_versions']))} "
                      f"→ {', '.join(map(text, comparison['after_versions']))} |",
                      f"| Original advisories | {advisory_links(comparison['original_advisories'])} |",
                      f"| Original advisories still reported | {advisory_links(comparison['original_advisories_remaining']) or 'None'} |",
                      f"| Advisories still reported for this dependency | {advisory_links(comparison['remaining_advisories']) or 'None'} |",
                      f"| Newly reported advisories | {advisory_links(comparison['new_advisories']) or 'None'} |", ""]
        lines += ["| Check | Result |", "| --- | --- |"]
        for index, check in enumerate(validation["checks"]):
            label, passed, detail = describe(check)
            if index == len(validation["checks"]) - 1 and validation["result"] != "pass":
                outcome = validation["result"].capitalize()
            else:
                outcome = "Pass" if passed else "Fail"
            lines.append(f"| {text(label)} | {outcome} {text(detail)} |")
        behavior = validation.get("security_behavior", [])
        if behavior:
            lines += ["", "**Maintained security behavior tests**", ""]
            for result in behavior:
                lines += [f"- {'Pass' if result['passed'] else 'Fail'} — npm {text(' '.join(result['command']))}"]
        else:
            lines += ["", "No focused security behavior test ran for this candidate."]
        lines += [""] + details("Command output and recorded checks",
                                [f"<pre>{html.escape(check)}</pre>" for check in validation["checks"]])
    lines += ["## 4. Agent verification of the tested change", ""]
    if validation := data.get("fix_validation"):
        lines += [f"- **Advisory resolution · {text(validation['verdict'])}** — {text(validation['rationale'])}",
                  f"- **Verification limits** — {text(validation['remaining_uncertainty'])}"]
    else:
        lines += ["- **Fix validation agent** — No verdict recorded."]
    if review := data.get("test_review"):
        lines += [f"- **Test review** — {text(review['summary'])}",
                  f"- **Behavior covered** — {text(review['behavior_covered'])}",
                  f"- **Coverage gaps** — {text(review['untested_behavior'])}"]
    if inspection := data.get("fix_inspection"):
        lines += [f"- **Final change inspection · {text(inspection['recommendation'])}** — "
                  f"{text(inspection['reasoning'])}",
                  f"- **Remaining compatibility risk** — {text(inspection['compatibility_risks'])}"]
    lines += ["", "## 5. Publication", ""]
    if escalation := data.get("escalation"):
        lines += [f"**Human review needed** — {text(escalation)}."]
    elif pull:
        number = int(pull["number"])
        url = pull["url"]
        if re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+", url):
            lines += [f"[Draft PR #{number}]({url}) is open for human review."]
        else:
            lines += [f"Draft PR {number} is open for human review."]
    elif draft := data.get("draft"):
        lines += ["Draft prepared for review. Files: " + ", ".join(map(text, draft["files"])) + "."]
    else:
        lines += ["No draft was published."]
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
