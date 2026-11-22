# Dependency AppSec workflow

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
        |   Triage agent reviews advisory facts and source references
        |     |
        |     +-- Assessment unavailable --> needs-triage
        |     +-- Exposure uncertain ------> Hunt agent reviews source and tests
        |     |                               |
        |     |                               v
        |     |                             Record evidence --> needs-validation
        |     |
        |     +-- Assessed as affected, fix available --> remediation-ready
        |     +-- Other assessed findings -------------> needs-human-review
        |
        +-- Existing remediation PR --> Track open or closed state
        +-- Affected version removed --> Mark fixed after a complete rescan
        |
        v
      Create or update the same GitHub Issue
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

Exposure validation records source and test evidence and can return `unable to validate`.
Test development proposes compatibility checks for human review. After an upgrade,
the executable gate runs the existing approved test suite.
