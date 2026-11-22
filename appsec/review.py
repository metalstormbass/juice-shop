"""Export a single GitHub reconciliation job's SQLite evidence for human review."""
import argparse
import html
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from urllib.parse import quote


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def cell(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("`", "&#96;")


def export(db_path, destination, mode):
    with closing(sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        records = defaultdict(dict)
        for namespace, key, value in db.execute("select namespace,key,value from records"):
            records[namespace][key] = json.loads(value)
        events = [(ns, key, json.loads(value)) for ns, key, value in db.execute(
            "select namespace,key,value from audit order by id")]
    if sum(ns == "run" for ns, _, _ in events) != 1:
        raise ValueError("Review requires a completed, single-run job database")
    scope, summary = next(iter(records["run"].items()))
    inventory = records["inventory"][scope]
    repo = inventory["repository"]
    slug, sha = repo["slug"], repo["revision"]
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", slug) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid GitHub source revision")
    source = f"https://github.com/{slug}/blob/{sha}/"
    lock_url = source + quote(repo["lockfile"])
    destination.mkdir(parents=True, exist_ok=True)
    for directory in ("findings", "calls"):
        (destination / directory).mkdir(exist_ok=True)
    write_json(destination / "inventory.json", inventory)
    write_json(destination / "changes.json", summary["changes"])
    deps = {d["path"]: d for d in inventory["dependencies"]}
    queries = sorted({(d["name"], d["version"]) for d in deps.values()
                      if d["registry"]["source"] == "public-npm"})
    write_json(destination / "scan-inputs.json", [{"name": n, "version": v} for n, v in queries])
    osv = [v for ns, _, v in events if ns == "osv-response"]
    if osv:
        with (destination / "osv.jsonl").open("w") as stream:
            for response in osv:
                print(json.dumps(response), file=stream)
    states = records["state:" + scope]
    dispositions = defaultdict(list)
    transitions = defaultdict(list)
    for ns, key, value in events:
        if ns == "agent-disposition":
            dispositions[key].append(value)
        elif ns == "transition":
            transitions[key].append(value)
    calls = [v for ns, _, v in events if ns == "agent-execution"]
    linked = defaultdict(list)
    call_rows = []
    for index, call in enumerate(calls, 1):
        digest = call["input_digest"]
        inputs = records["agent-inputs"].get(digest)
        request_key = f"{call['role']}:{call['model']}:{digest}"
        output = records["agent-results"].get(request_key)
        key = inputs["facts"]["finding_id"] if inputs else None
        reason = next((d["reason"] for d in dispositions[key] if d["input_digest"] == digest
                       and d["role"] == call["role"]), None)
        reason = reason or ("Accepted structured output" if output else "Failure reason unavailable in original audit")
        filename = f"calls/{index:02}.json"
        linked[key].append(filename)
        evidence = [{**ref, "source_url": source + quote(ref["path"]) + f"#L{ref['line']}"}
                    for ref in inputs["evidence"]] if inputs else []
        write_json(destination / filename, {"execution": call, "decision": reason, "input": inputs,
                                           "request_settings": records["agent-request-settings"].get(request_key),
                                           "accepted_output": output, "source_evidence": evidence})
        package = inputs["facts"]["package"] if inputs else "Unrecorded"
        call_rows.append(f"| [{index}]({filename}) | {cell(call['role'])} | {cell(package)} | "
                         f"{cell(call['outcome'])} | {cell(reason)} |")
    counts = Counter(state["status"] for state in states.values())
    def describe(counter):
        return ", ".join(f"{count} {cell(label)}" for label, count in sorted(counter.items()))

    lines = [
        "# Reconciliation review", "",
        f"Commit [`{sha[:12]}`](https://github.com/{slug}/commit/{sha}) · mode **{mode}**", "",
        "| Step | Input | Output | How to check |", "|---|---|---|---|",
        f"| 1. Inventory | [Lockfile at the scanned revision]({lock_url}) | {len(deps)} dependency paths | "
        "Compare a lockfile packages entry to the same path in [inventory.json](inventory.json). |",
        f"| 2. Inventory diff | Current inventory and available baseline | "
        f"{describe(Counter(summary['changes'].values()))} | Inspect [changes by path](changes.json). "
        "A fresh database without a baseline reports each path as added. |",
        f"| 3. OSV query | [Public npm names and exact versions](scan-inputs.json) | "
        f"{len(queries)} distinct inputs, {len(summary['coverage_gaps'])} skipped paths | "
        + ("Match each query to the result at the same array index in [OSV exchanges](osv.jsonl). |" if osv
           else "Original audit retained normalized advisories only. Check their OSV provenance URLs. |"),
        f"| 4. Normalize | OSV advisory IDs, aliases and affected ranges | {len(summary['findings'])} findings | "
        "Open a finding below. Compare its advisory and fix candidates with its installed paths. |",
        f"| 5. Triage and hunt | Finding, source excerpts and upstream assessment | {len(calls)} OpenAI calls | "
        "Open the numbered call. Compare its accepted output and cited evidence IDs with the input. |",
        f"| 6. Exposure validation | Hunt evidence | {len(records['validation'])} validation records | "
        "Check exposure_validation.checks in the finding file for what was actually tested. |",
        f"| 7. Reconcile | Findings, assessments and prior state | {describe(counts)} | "
        "Inspect transitions and final state per finding. |",
        "| 8. GitHub sync | Reconciliation mode | " +
        ("Skipped in dry-run mode" if mode == "dry-run" else f"{len(records['issue'])} issue identities recorded")
        + " | See issue_number in each finding. |",
        "| 9. Remediation, fix tests and draft PR | Separate manual workflow | Skipped during reconciliation | "
        "A remediation-ready state records eligibility only. |", "",
        "## OpenAI calls", "", "| Call | Role | Package | Outcome | Check |", "|---|---|---|---|---|",
        *call_rows, "", "## Findings", "",
        "| Package and version | Advisory | Final state | Trace |", "|---|---|---|---|"]
    for key, state in sorted(states.items(), key=lambda pair: (pair[1]["package"], pair[0])):
        if not re.fullmatch(r"[a-f0-9]{32}", key):
            raise ValueError("Invalid finding identifier")
        finding = records["finding"].get(key)
        filename = f"findings/{key}.json"
        paths = {p: deps.get(p) for p in state.get("paths", [])}
        write_json(destination / filename, {"finding_id": key, "installed_dependencies": paths,
                    "normalized_finding": finding, "agent_calls": linked[key],
                    "agent_decisions": dispositions[key], "exposure_validation": records["validation"].get(key),
                    "transitions": transitions[key], "state": state, "issue_number": records["issue"].get(key)})
        lines.append(f"| {cell(state['package'])}@{cell(state['version'])} | {cell(', '.join(state['aliases']))} | "
                     f"{cell(state['status'])} | [Inspect]({filename}) |")
    (destination / "README.md").write_text("\n".join(lines) + "\n")
    return lines


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path("appsec.sqlite"))
    parser.add_argument("--out", type=Path, default=Path("review"))
    parser.add_argument("--mode", choices=("dry-run", "apply"), required=True)
    args = parser.parse_args()
    lines = export(args.db, args.out, args.mode)
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        # Artifact-relative links work in the downloaded report. Show filenames on GitHub.
        summary = re.sub(r"\[([^\]]+)\]\(((?!https://)[^()]+)\)", r"\1 (`\2`)", "\n".join(lines))
        with open(summary_path, "a") as stream:
            print(summary, file=stream)
