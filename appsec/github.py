import base64
import os
import html
import json
import re
from urllib.parse import urlencode

from .models import PullRequest
from .store import encoded
from .transport import RequestFailed, request

MARKER = re.compile(r"<!-- appsec-state:([a-zA-Z0-9_-]+) -->")
STATES = {"needs-triage", "needs-validation", "remediation-ready", "remediation-in-progress",
          "needs-human-review", "fixed", "risk-accepted"}
LABELS = {"appsec", "vulnerability", *STATES}


def marker(state):
    data = encoded(state).encode()
    return "<!-- appsec-state:" + base64.urlsafe_b64encode(data).decode().rstrip("=") + " -->"


def read_marker(issue):
    match = MARKER.search(issue.get("body") or "")
    if not match:
        return None
    data = match[1]
    try:
        state = json.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))
        if isinstance(state, dict) and re.fullmatch(r"[a-f0-9]{32}", state.get("id", "")):
            return state
    except (ValueError, TypeError):
        pass
    return None


def protected(text):
    return "<pre>" + html.escape(text).replace("@", "&#64;") + "</pre>"


def issue_payload(finding, state, assessment=None, validation=None, refs=()):
    title = f"[AppSec] {finding.package}@{finding.installed_version} ({finding.advisory_ids[0]})"
    facts = {"advisories": finding.advisory_ids, "package": finding.package,
             "installed_version": finding.installed_version, "paths": finding.dependency_paths,
             "severity": finding.severity, "fix_versions": finding.fix_versions,
             "references": finding.references}
    prior = state.get("display", {})
    display = {**prior, "assessment": assessment or prior.get("assessment"),
               "validation": validation or prior.get("validation"),
               "evidence": list(refs) or prior.get("evidence", [])}
    heading = (f"## Finding\n\nID `{state['id']}`. Lifecycle state is **{state['status']}**.\n\n")
    body = (heading
            + protected(json.dumps({**facts, **display}, indent=2)) + "\n\n"
            + marker({**state, "display": display}))
    if len(body.encode()) > 60_000:
        display = {"note": "Full evidence exceeds the issue size limit. See the run artifacts."}
        body = heading + protected(
            json.dumps({**facts, **display}, indent=2)[:20_000]) + "\n\n" + marker(
                {key: value for key, value in state.items() if key != "display"})
    return {"title": title[:240], "body": body, "labels": ["appsec", "vulnerability", state["status"]]}


class GitHub:
    def __init__(self, slug, token, send=request):
        self.url = "https://api.github.com/repos/" + slug
        self.send = send
        self.headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}

    def call(self, method, path, data=None):
        # Ambiguous writes are retried by reconciliation after reading remote state.
        return self.send(method, self.url + path, data, self.headers,
                         attempts=3 if method == "GET" else 1)

    def pages(self, path, **params):
        for page in range(1, 101):
            items = self.call("GET", path + "?" + urlencode({**params, "per_page": 100, "page": page}))
            yield from items
            if len(items) < 100:
                return
        raise ValueError("GitHub pagination limit exceeded")

    def issues(self):
        actor = os.environ.get("APPSEC_GITHUB_ACTOR", "github-actions[bot]")
        return [(issue, state) for issue in self.pages("/issues", state="all", labels="appsec,vulnerability")
                if "pull_request" not in issue and issue.get("user", {}).get("login") == actor
                and (state := read_marker(issue))]

    def ensure_labels(self):
        existing = {label["name"] for label in self.pages("/labels")}
        for label in sorted(LABELS - existing):
            self.call("POST", "/labels", {"name": label, "color": "b60205"})

    def sync(self, current, payload):
        if current is None:
            return self.call("POST", "/issues", payload)
        other = sorted({label["name"] for label in current["labels"]} - LABELS)
        payload = {**payload, "labels": sorted(set(payload["labels"]) | set(other))}
        unchanged = all(current.get(key) == value for key, value in payload.items() if key != "labels")
        if unchanged and sorted(label["name"] for label in current["labels"]) == payload["labels"]:
            return current
        return self.call("PATCH", f"/issues/{current['number']}", payload)

    def default_head(self):
        branch = self.call("GET", "")["default_branch"]
        head = self.call("GET", f"/git/ref/heads/{branch}")["object"]["sha"]
        return branch, head

    def pulls(self, branch, state="all"):
        owner = self.url.split("/")[-2]
        return list(self.pages("/pulls", head=f"{owner}:{branch}", state=state))

    def draft(self, repository, issue, finding, files, validation, narrative):
        base, head = self.default_head()
        if head != repository.revision:
            raise RuntimeError("Default branch changed during remediation")
        branch = f"appsec/{finding.finding_id}/{head[:12]}"
        existing = self.pulls(branch)
        if existing:
            pull = existing[0]
            return PullRequest(number=pull["number"], url=pull["html_url"], branch=branch)
        parent = self.call("GET", f"/git/commits/{head}")
        tree = self.call("POST", "/git/trees", {"base_tree": parent["tree"]["sha"],
                         "tree": [{"path": path, "mode": "100644", "type": "blob", "content": content}
                                  for path, content in sorted(files.items())]})
        try:
            ref = self.call("GET", f"/git/ref/heads/{branch}")
        except RequestFailed as error:
            if error.status != 404:
                raise
            ref = None
        if ref:
            commit = self.call("GET", f"/git/commits/{ref['object']['sha']}")
            if commit["tree"]["sha"] != tree["sha"] or [p["sha"] for p in commit["parents"]] != [head]:
                raise RuntimeError("Existing remediation ref differs from validated change")
        else:
            version = validation.version
            committer = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
            identity = {"name": "github-actions[bot]",
                        "email": "41898282+github-actions[bot]@users.noreply.github.com",
                        "date": parent["author"]["date"]}
            commit = self.call("POST", "/git/commits", {
                "message": f"Upgrade {finding.package} to {version}\n\nSigned-off-by: {committer}",
                "tree": tree["sha"], "parents": [head],
                "author": identity, "committer": identity})
            self.call("POST", "/git/refs", {"ref": "refs/heads/" + branch, "sha": commit["sha"]})
        summary = {"affected": f"{finding.package}@{finding.installed_version}",
                   "advisories": finding.advisory_ids, "upgrade": validation.version,
                   "validation": validation.validation.model_dump(), "analysis": narrative}
        body = f"Related issue #{issue['number']}. Human review required.\n\n" + protected(
            json.dumps(summary, indent=2)[:40_000])
        pull = self.call("POST", "/pulls", {"title": f"Upgrade {finding.package} to {validation.version}",
                         "body": body, "head": branch, "base": base, "draft": True})
        return PullRequest(number=pull["number"], url=pull["html_url"], branch=branch)
