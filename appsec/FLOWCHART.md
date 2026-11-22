# Dependency AppSec workflow

## Automated workflow

Runs when `package.json` or `package-lock.json` changes on the default branch
or on manual dispatch. At most three AppSec PRs are open at once.

```text
package.json or package-lock.json changes
  |
  +-- Pull request --> Scan the candidate dependency graph without write access
  |
  +-- Default branch --> Reconcile the committed dependency graph
                           |
                           v
                    Open GitHub Issues track every finding
                           |
                           v
                    Queue eligible findings, at most (3 - open AppSec PRs),
                    one parallel job each
                           |
                           v
                    Agents review compatibility and propose tests
                           |
                           v
                    Upgrade within the same major version, regenerate the lockfile
                           |
                           v
                    Independent verification: OSV rescan, npm ci, sqlite3 rebuild,
                    server unit tests and a TypeScript compile check
                           |
                           +-- Upgrade exposes other advisories --> retry with the
                           |     OSV fix version that clears them (attempt limit applies)
                           |
                           v
                    AI test review reads the results, names the behavior the
                    existing tests exercise and what they do not cover
                           |
                           +-- Passed --> One draft PR per finding, then independent
                           |              PR validation
                           |
                           +-- Failed or no same-major fix --> Reason and AI test review
                                          recorded on the finding's issue; no PR is opened

Draft PR layout:
  1. The finding       package, versions, severity, advisories, advisory summary
  2. Why it affects    AI explanation of how this code uses the package, with source links
     this code
  3. Why this fix      AI rationale, compatibility risk, versions tried before
  4. Testing           pass/fail table (install, rebuild, unit tests with counts,
                       compile check), AI test review, remaining uncertainty,
                       raw command output
```

Every finding has an issue. To stay within free Actions limits, a run queues only
eligible findings (fixable, not risk-accepted, not already attempted at this revision)
up to the number of free slots under a cap of three open AppSec PRs. Merging or closing
PRs frees slots; the next manifest change or manual dispatch continues with the
remaining findings. There is no schedule. PRs always come from verified upgrades against the
committed default branch, so a finding with no passing same-major fix gets no PR.
Merging a PR changes the manifests and starts the next run for the remaining findings.

## Detailed stages

```text
npm package-lock.json (v2 or v3)
  |
  v
Dependency inventory
  |-- Record names, exact versions, paths, sources, and dependency relationships
  |-- Compare against the previous inventory or PR base
  |-- Report private or unsupported sources as coverage gaps
  v
OSV scan of public npm packages
  |-- Batch exact-version queries, fetch advisories, group aliases
  |
  +-- Pull request scan --> Publish summary and inventory artifact
  |
  +-- Scheduled or manual reconciliation
        |
        v
      Match current findings to SQLite records and GitHub Issues
        |
        +-- Human applied risk-accepted --> Preserve that decision
        |
        +-- New or changed finding
        |     |
        |     v
        |   Prioritize findings with static evidence of application use
        |     |
        |     v
        |   OpenAI triage reviews advisory and repository evidence
        |     |-- Advisory prerequisites and affected behavior
        |     |-- Installed dependency paths and parent packages
        |     |-- Application imports and candidate calls
        |     |-- Input provenance, deployment scope and observed controls
        |     |-- Impact, local priority, citations and missing evidence
        |     |
        |     +-- Deferred or rejected output --> needs-triage
        |     +-- Uncertain exposure --> Hunt reviews source and tests
        |     |                            |
        |     |                            v
        |     |                  Record evidence --> needs-validation
        |     +-- Confirmed exposure with an OSV fix --> remediation-ready
        |     +-- Other assessed findings ------------> needs-human-review
        |
        +-- Existing remediation PR --> Track open or closed state
        +-- Affected version removed --> Mark fixed after a complete rescan
        |
        v
      Publish a readable GitHub Actions summary with expandable findings
        |-- Dry run --> Report and evidence artifact
        |-- Apply --> Create or update the same GitHub Issue
        |
        v
Maintainer requests remediation by finding ID
  |
  v
Remediation agent reviews upgrade compatibility
Test development agent proposes behavior to cover
  |
  v
Select a same-major fix candidate from OSV
Update the manifest and regenerate the lockfile with npm in isolation
  |
  v
Independent fix validation
  |-- Check that the original version is absent
  |-- Rescan for the original advisory and new findings
  |-- Run npm ci and the approved existing test suite
  |
  +-- Failed -------> Try another candidate within the retry limit
  +-- Inconclusive or exhausted --> needs-human-review
  |
  +-- Passed --> PR agent summarizes the change and evidence
                   |
                   v
                 GitHub creates or reuses a draft PR
                   |
                   v
                 Read-only PR validation --> Human review and merge
                                                  |
                                                  v
                                        Next reconciliation rescans
                                        and updates the original issue
```

## Verified GitHub status

The risk-triage dry run completed on the AppSec branch. It inventoried 1,248
dependency paths and reported 54 findings. Eight OpenAI calls produced three
accepted triage assessments and three follow-up investigations. Two triage
outputs were rejected for invalid citations.

- **51 need triage**
- **3 need validation**
- **0 were marked ready for remediation**

The dry run ended at reporting. Issue synchronization, dependency edits,
fix validation, and draft PR creation require their respective apply or
remediation workflows.

[GitHub Actions run](https://github.com/metalstormbass/juice-shop/actions/runs/45070764850) · [Risk decisions and source citations](https://github.com/metalstormbass/juice-shop/blob/5d045132dbc88ca09e105c58719c06a6dd198b80/appsec/reports/run-45070764850.md#risk-decisions)

## Evidence limits

Confirmation requires cited advisory prerequisites, a candidate application call,
and evidence of input provenance. Static excerpts can leave runtime behavior
and deployment conditions unresolved.

Exposure validation records source and test evidence and can return `unable to validate`.
Test development proposes compatibility checks for human review. After an upgrade,
the executable gate runs the existing approved test suite.
