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
[AGENT: triage] assess exposure → [AGENT: hunt] investigate uncertainty
  │
  ▼
Sync finding issues
  │
  ▼
Group by package and proposed version → Queue one update per package
  │                                      (up to three open AppSec PRs)
  │
  ├─ Risk accepted, PR in progress, or already attempted at this revision → Skip
  ▼
[AGENT: remediation] review compatibility
  │
  ▼
[AGENT: test-development] propose compatibility checks → npm updates dependency
  │
  ▼
Regenerate lockfile → Compare graph and OSV findings
  │
  ├─ New advisories on target → Try an eligible OSV fix within the attempt limit
  ▼
Clean install → Rebuild sqlite3 → Server unit tests → TypeScript check
  │
  ▼
Run maintained security behavior tests when configured for the dependency
  │
  ├─ Failed or inconclusive → Record outcome; escalate if no candidate passes
  ▼
[AGENT: test-review] interpret recorded test evidence
  │
  ▼
[AGENT: fix-validation] review before/after OSV and executed security behavior checks
  │
  ├─ Unresolved, inconclusive or unavailable → Human review
  ▼
[AGENT: fix-inspection] review the exact tested version, manifest entry, lockfile
changes, dependency chain, attempt history and verification checks
  │
  ├─ Missing review or escalation → Human review
  ▼
[AGENT: pr] draft explanatory text → GitHub creates draft PR
  │
  ▼
Independent PR verification → Human review
  │
  └─ Merge changes manifests → Rescan on the next reconciliation
```

Each AGENT label marks an OpenAI role. Execution records distinguish live calls from cached, skipped or rejected assessments. The automatic queue retains related finding IDs for the same proposed update. A passing rescan determines which advisories the final version addresses. The cap applies when the reconciliation job builds its matrix. The separately dispatched manual remediation workflow selects a finding by ID.

## Checking the evidence

| Step | What to inspect |
| --- | --- |
| Inventory | Compare each dependency path and version in the lockfile with the inventory artifact. [Reconciliation run](https://github.com/metalstormbass/juice-shop/actions/runs/45077134734) |
| OSV matching | In the reconciliation artifact, open `review/README.md` and follow a finding to its installed paths, advisory IDs, and OSV exchanges. |
| Triage and hunt | The run summary shows source citations, local priority and missing evidence. Agent records distinguish accepted, rejected and deferred calls. |
| Issue and queue | Match the finding ID on the issue with the remediation artifact name and the queue in `summary.json`. [Example issue](https://github.com/metalstormbass/juice-shop/issues/181) |
| Candidate selection | Compare the original version, versions tried, advisory outcomes and final manifest diff. [Example PR files](https://github.com/metalstormbass/juice-shop/pull/203/files) |
| Compatibility | Read the command outcomes and raw output in the PR. For the tested `moment` update, 441 server tests passed, zero failed and two were skipped. TypeScript compilation passed. Frontend and API suites are outside the configured checks. [Test results](https://github.com/metalstormbass/juice-shop/pull/203) |
| Advisory resolution | The remediation job summary shows installed versions, the original advisory IDs, any that remain, newly reported advisories, and the fix validation agent’s verdict and limits. |
| Fix inspection | The inspector receives the final manifest entry, changed lockfile paths and versions, a digest of both files, and the verified attempt history. Its recommendation and compatibility risks appear under “Why this fix.” Unavailable inspection blocks publication. |
| Independent verification | The matrix dispatches another workflow for a newly opened PR. Check its conclusion separately from the reconciliation job. [Successful independent run](https://github.com/metalstormbass/juice-shop/actions/runs/45077897093) |

PR #203 was created before the mandatory final inspection was introduced. Its retrospective inspection is identified separately on the PR. The deterministic checks establish the dependency change and tested behavior. Agent assessments describe remaining uncertainty.
