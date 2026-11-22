import hashlib
from collections import defaultdict
from urllib.parse import quote

from .exposure import advisory_context
from .models import Advisory, Finding
from .transport import request

BASE = "https://api.osv.dev/v1"


class OSV:
    def __init__(self, send=request, store=None):
        self.send = send
        self.store = store

    def fetch(self, method, url, data=None):
        result = self.send(method, url, data) if data is not None else self.send(method, url)
        if self.store:
            self.store.event("osv-response", url, {"method": method, "url": url,
                             "input": data, "output": result})
        return result

    def scan(self, inventory):
        paths = defaultdict(list)
        for dependency in inventory.dependencies:
            if dependency.registry.source == "public-npm":
                paths[dependency.name, dependency.version].append(dependency.path)

        details = {}
        findings = []
        keys = sorted(paths)
        for start in range(0, len(keys), 100):
            batch = keys[start:start + 100]
            queries = [{"package": {"ecosystem": "npm", "name": name}, "version": version}
                       for name, version in batch]
            ids = [set() for _ in batch]
            pending = {i: query for i, query in enumerate(queries)}
            for _ in range(30):
                if not pending:
                    break
                page = self.fetch("POST", BASE + "/querybatch", {"queries": list(pending.values())})
                results = page["results"]
                if len(results) != len(pending):
                    raise ValueError("OSV result count differs from query count")
                next_page = {}
                for (index, query), result in zip(pending.items(), results):
                    ids[index].update(item["id"] for item in result.get("vulns", []))
                    if token := result.get("next_page_token"):
                        if token == query.get("page_token"):
                            raise ValueError("OSV pagination did not progress")
                        next_page[index] = {**query, "page_token": token}
                pending = next_page
            if pending:
                raise ValueError("OSV page limit exceeded")
            for (name, version), advisory_ids in zip(batch, ids):
                records = []
                for identifier in sorted(advisory_ids):
                    if identifier not in details:
                        url = BASE + "/vulns/" + quote(identifier, safe="")
                        raw = self.fetch("GET", url)
                        if raw["id"] != identifier:
                            raise ValueError("OSV advisory identifier mismatch")
                        details[identifier] = None if raw.get("withdrawn") else Advisory(
                            id=identifier, modified=raw["modified"], aliases=raw.get("aliases", []),
                            summary=raw.get("summary", ""), conditions_text=advisory_context(raw.get("details", "")),
                            severity=raw.get("severity", []),
                            references=sorted({ref["url"] for ref in raw.get("references", [])
                                               if ref["url"].startswith("https://")}),
                            affected=raw.get("affected", []), provenance=url)
                    if record := details[identifier]:
                        records.append(record)
                for group, aliases in overlap(records):
                    fixes = set()
                    for record in group:
                        for affected in record.affected:
                            if affected.get("package", {}).get("name") != name or affected.get("package", {}).get("ecosystem") != "npm":
                                continue
                            fixes.update(event["fixed"] for span in affected.get("ranges", [])
                                         if span.get("type") == "SEMVER" for event in span["events"] if "fixed" in event)
                    # Historical alias matches preserve the original identity when OSV adds aliases.
                    identity = next((alias for alias in sorted(aliases) if alias.startswith("GHSA-")), min(aliases))
                    repo = inventory.repository
                    digest = hashlib.sha256(f"{repo.slug}:{repo.lockfile}:{name}:{version}:{identity}".encode()).hexdigest()[:32]
                    findings.append(Finding(finding_id=digest, package=name, installed_version=version,
                                            dependency_paths=paths[name, version], advisory_ids=sorted(aliases),
                                            severity="; ".join(sorted({entry["score"] for record in group
                                                                       for entry in record.severity})) or "unknown",
                                            fix_versions=sorted(fixes), references=sorted({url for record in group
                                                                                           for url in record.references}),
                                            advisories=group))
        return findings


def overlap(records):
    groups = []
    for record in records:
        aliases = {record.id, *record.aliases}
        group = [record]
        remaining = []
        for existing, identifiers in groups:
            if aliases & identifiers:
                aliases |= identifiers
                group.extend(existing)
            else:
                remaining.append((existing, identifiers))
        groups = remaining + [(group, aliases)]
    return groups
