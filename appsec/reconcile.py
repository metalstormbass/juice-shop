from .agents import evidence
from .exposure import graph_context, options_for
from .github import MARKER, issue_payload, marker
from .models import Finding, Transition
from .store import digest
from .validation import review_exposure


def matching(finding, state):
    return (state.get("package") == finding.package and state.get("version") == finding.installed_version
            and bool(set(state.get("aliases", [])) & set(finding.advisory_ids)))


def reconcile(root, inventory, findings, store, agents, github=None, write=True):
    scope = f"{inventory.repository.slug}:{inventory.repository.lockfile}"
    states = store.all("state:" + scope)
    remote = {}
    if github:
        for issue, state in github.issues():
            if state.get("scope") == scope:
                remote[state["id"]] = issue
                states[state["id"]] = state
        if write:
            github.ensure_labels()

    def save(state, finding, refs=()):
        key = state["id"]
        before = states.get(key, {}).get("status")
        if before != state["status"]:
            event = Transition(finding_id=key, before=before, after=state["status"], reason=state["reason"])
            store.event("transition", key, event)
        store.put("state:" + scope, key, state)
        if github and write:
            issue = github.sync(remote.get(key), issue_payload(finding, state, refs=refs))
            store.put("issue", key, issue["number"])
        elif github and key in remote:
            store.put("issue", key, remote[key]["number"])
        states[key] = state

    seen = set()
    output = []
    queue = []
    packages = {}
    for scanned in findings:
        identity = next((key for key, old in sorted(states.items()) if matching(scanned, old)), scanned.finding_id)
        finding = scanned.model_copy(update={"finding_id": identity})
        key = (finding.package, tuple(finding.dependency_paths))
        if key not in packages:
            graph = graph_context(inventory, finding)
            options = options_for(inventory, finding)
            aliases = options["aliases"]
            references = evidence(root, finding.package, **options)
            resolvable = any(path == "node_modules/" + alias for path, alias in zip(finding.dependency_paths, aliases))
            kinds = {ref.kind for ref in references}
            # Spend bounded triage calls first on findings with observed application use.
            rank = (not (resolvable and "project call candidate" in kinds),
                    not (resolvable and "project import" in kinds),
                    not any(d["type"] == "production" for d in graph["installed"]))
            packages[key] = rank, options, references, graph, resolvable
        rank, options, references, graph, resolvable = packages[key]
        queue.append((rank, finding, options, references, graph, resolvable))

    for _, finding, options, references, graph, resolvable in sorted(queue, key=lambda entry: entry[0]):
        identity = finding.finding_id
        seen.add(identity)
        old = states.get(identity, {})
        fact_hash = digest(finding)
        refs = [item.model_dump() for item in references]
        context = {"dependency_scope": graph, "root_resolvable": resolvable,
                   "input_origin_ids": [ref.id for ref in references if ref.kind == "input origin at call"],
                   "advisory_context": [{"id": record.id, "description": record.conditions_text,
                                         "summary": record.summary, "source": record.provenance}
                                        for record in finding.advisories[:4]]}
        fingerprint = digest(["risk-triage-v3", fact_hash, refs, context])
        labels = {label["name"] for label in remote.get(identity, {}).get("labels", [])}
        accepted = "risk-accepted" in labels
        display = old.get("display", {}) if old.get("fingerprint") == fingerprint else {}
        status = "needs-triage"
        reason = "OSV matched an exact public npm version"
        if accepted:
            status, reason = "risk-accepted", "Risk acceptance explicitly labeled on GitHub"
        elif old.get("pull") and github:
            pull = github.call("GET", f"/pulls/{int(old['pull'])}")
            if pull["state"] == "open":
                status, reason = "remediation-in-progress", "Draft remediation is open"
            else:
                status, reason = "needs-human-review", "Remediation PR closed and OSV still reports the finding"
        elif old.get("status") == "needs-human-review" and old.get("fingerprint") == fingerprint:
            status, reason = old["status"], old["reason"]
        elif not write:
            # Read-only passes reuse the recorded decision and never spend agent calls on triage.
            status, reason = old.get("status", status), old.get("reason", reason)
            display = old.get("display", display)
        else:
            if not display.get("assessment"):
                assessment = agents.run("triage", finding, references, **context)
                if assessment:
                    display = {"assessment": assessment.model_dump(), "evidence": refs}
            assessment = display.get("assessment")
            if assessment:
                status = "needs-human-review"
                classification = assessment["classification"]
                if classification in ("potentially affected", "unknown"):
                    if not display.get("investigation"):
                        expanded = evidence(root, finding.package, limit=24, **options)
                        investigation = agents.run("hunt", finding, expanded, assessment=assessment)
                        if investigation:
                            display["hunt_evidence"] = [item.model_dump() for item in expanded]
                            display["investigation"] = investigation.model_dump()
                        validation = review_exposure(investigation, expanded)
                        display["validation"] = validation.model_dump()
                    store.put("validation", identity, display["validation"])
                    status = "needs-validation"
                elif classification == "confirmed affected" and finding.fix_versions:
                    status = "remediation-ready"
        state = {"id": identity, "scope": scope, "package": finding.package,
                 "version": finding.installed_version, "aliases": finding.advisory_ids,
                 "status": status, "reason": reason, "fingerprint": fingerprint,
                 "fact_hash": fact_hash, "display": display, "paths": finding.dependency_paths,
                 "pull": old.get("pull"), "attempted_revision": old.get("attempted_revision")
                 if old.get("fingerprint") == fingerprint else None}
        store.put("finding", identity, finding)
        save(state, finding, refs)
        output.append(finding)

    if not write:
        return output
    for key, old in list(states.items()):
        labels = {label["name"] for label in remote.get(key, {}).get("labels", [])}
        if key in seen or old.get("status") == "fixed" or "risk-accepted" in labels:
            continue
        candidates = [dep for dep in inventory.dependencies if dep.name == old.get("package")]
        # A source change creates a coverage gap even if the package name moved to an alias.
        previous_paths = set(old.get("paths", []))
        if any(dep.registry.source != "public-npm" and
               (dep in candidates or dep.path in previous_paths) for dep in inventory.dependencies):
            continue
        if any(dep.version == old.get("version") for dep in candidates):
            continue
        if any(item.package == old.get("package") and set(item.advisory_ids).intersection(old.get("aliases", []))
               for item in output):
            continue
        record = store.get("finding", key)
        state = {**old, "status": "fixed", "reason": "Exact affected version absent after a complete scan"}
        if record:
            save(state, Finding.model_validate(record))
        elif key in remote:
            issue = remote[key]
            # The issue retains its original facts when the runner has no local history.
            body = MARKER.sub("", issue["body"]).strip()
            _, separator, remainder = body.partition("<pre>")
            payload = {"title": issue["title"], "body": f"ID `{key}`. Lifecycle state is **fixed**. " + state["reason"]
                       + "\n\n" + separator + remainder + "\n\n" + marker(state),
                       "labels": ["appsec", "vulnerability", "fixed"]}
            github.sync(issue, payload)
            store.put("state:" + scope, key, state)
    return output
