# From a dependency change to a tested fix

A pull request gets a read-only dependency scan. On the default branch, a change to the root npm manifest or lockfile triggers reconciliation. A maintainer can also dispatch reconciliation manually.

```text
Dependency PR ──► Compare base and candidate lockfiles ──► Read-only scan summary

Default-branch manifest change or manual reconciliation
  │
  ▼
Inventory paths and versions → Query OSV → Group advisories into findings
  │
  ▼
Triage application evidence → Hunt if exposure is uncertain → Sync finding issues
  │
  ▼
Queue same-major fix candidates within available slots (three open AppSec PRs)
  │
  ├─ Risk accepted, PR in progress, or already attempted at this revision → Skip
  ▼
Remediation agent reviews compatibility → npm updates one target dependency
  │
  ▼
Regenerate lockfile → Compare graph and OSV findings
  │
  ├─ New advisories on target → Try an eligible OSV fix within the attempt limit
  ▼
Clean install → Rebuild sqlite3 → Server unit tests → TypeScript check
  │
  ├─ Failed or inconclusive → Record outcome; escalate if no candidate passes
  ▼
Test-review agent interprets available test evidence
  │
  ▼
Fix inspector reviews the exact tested version, manifest entry, lockfile
changes, dependency chain, attempt history and verification checks
  │
  ├─ Missing review or escalation → Human review
  ▼
Draft PR for the selected finding → Independent PR verification → Human review
  │
  └─ Merge changes manifests → Rescan on the next reconciliation
```

The automatic queue works per finding. Multiple advisories can describe the same dependency. The cap applies when the reconciliation job builds its matrix. The separately dispatched manual remediation workflow selects a finding by ID.

## Checking the evidence

| Step | What to inspect |
| --- | --- |
| Inventory | Compare each dependency path and version in the lockfile with the inventory artifact. [Reconciliation run](https://github.com/metalstormbass/juice-shop/actions/runs/45077134734) |
| OSV matching | In the reconciliation artifact, open `review/README.md` and follow a finding to its installed paths, advisory IDs, and OSV exchanges. |
| Triage and hunt | The run summary shows source citations, local priority and missing evidence. Agent records distinguish accepted, rejected and deferred calls. |
| Issue and queue | Match the finding ID on the issue with the remediation artifact name and the queue in `summary.json`. [Example issue](https://github.com/metalstormbass/juice-shop/issues/181) |
| Candidate selection | Compare the original version, versions tried, advisory outcomes and final manifest diff. [Example PR files](https://github.com/metalstormbass/juice-shop/pull/203/files) |
| Compatibility | Read the command outcomes and raw output in the PR. For the tested `moment` update, 441 server tests passed, zero failed and two were skipped. TypeScript compilation passed. Frontend and API suites are outside the configured checks. [Test results](https://github.com/metalstormbass/juice-shop/pull/203) |
| Fix inspection | The inspector receives the final manifest entry, changed lockfile paths and versions, a digest of both files, and the verified attempt history. Its recommendation and compatibility risks appear under “Why this fix.” Unavailable inspection blocks publication. |
| Independent verification | The matrix dispatches another workflow for a newly opened PR. Check its conclusion separately from the reconciliation job. [Successful independent run](https://github.com/metalstormbass/juice-shop/actions/runs/45077897093) |

PR #203 was created before the mandatory final inspection was introduced. Its retrospective inspection is identified separately on the PR. The deterministic checks establish the dependency change and tested behavior. Agent assessments describe remaining uncertainty.
