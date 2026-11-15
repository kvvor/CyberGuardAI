# Full rework checkpoint

Branch: `feature/full-rework`. Initial tree clean at `7115869`; reviewed WIP
`a5f0f69` and preserved its OpenAI/encryption/URL changes.

Implementation checklist (unchecked items are not complete):

- [x] Audit branch, history, parser/API/provider/frontend structure and migrations.
- [ ] Complete shared per-user encrypted provider settings and test both providers.
- [ ] VirusTotal hash-only client, independent consent, persistence and UI.
- [ ] Structured authentication and deterministic evidence IDs.
- [ ] Replace weighted final classification with validated OpenAI verdicts.
- [x] Remove active demo and MITRE features, preserve historical readability.
- [ ] Provider settings, analyzer, compact reports, dashboard and three languages.
- [ ] Portable configuration and Windows startup/install scripts.
- [ ] Full backend/frontend/PostgreSQL/end-to-end validation and documentation.

Baseline: existing application still uses heuristic scores and hybrid adjustments;
provider table supports only OpenAI; frontend settings has no provider controls.
Existing parser already hashes attachments; existing OpenAI uses Responses with
strict JSON schema and validates indicator IDs and exact contextual quotes.
Existing migrations 000001 and 000002 must be preserved; extend additively.

No live provider calls, pushes, database deletion or destructive Git operations
are authorized by this implementation workflow.

## Verified provider increment

- Shared provider service now scopes AES-GCM associated data and PostgreSQL rows
  by provider and owner. Migration 000003 preserves OpenAI data and adds VT quotas.
- VirusTotal hash-only client, explicit per-analysis consent, deduplication,
  bounded requests, error states, JSON persistence and PDF reputation fields.
- Functional OpenAI/VirusTotal Settings, analyzer configuration status, independent
  consent and attachment reputation UI, translated into en/ru/kk.
- `go build ./...`, `go vet ./...`, and `go test -count=1 ./...` passed, including
  isolated PostgreSQL tests after migrating cyberguard_test. Test credentials
  were loaded without printing from the existing sibling worktree configuration;
  no production database was touched.
- `npm.cmd ci`, `npm.cmd run test` (41 tests), `npm.cmd run lint`,
  `npm.cmd run build` passed. Build emits a nonfatal chunk size warning.
- Mocked VT tests cover HTTP status mapping, invalid/oversized data, redirects,
  network failures, timeout, duplicate hashes and quota denial.
- Initial OpenAPI validation failed on an unquoted comma; corrected and rerun.
- No live provider or browser end-to-end test ran.

Not a completed full rework: legacy classification, demo, MITRE, authentication
evidence redesign, Windows scripts and large attachment batch scheduling remain.
See virustotal.md for provider scope and licensing constraints.

## Verified live verdict increment

Live analysis now calls PrepareEvidence and uses validated OpenAI verdict directly;
Hybrid is no longer authoritative. Model input excludes legacy scores and keyword
judgments. Added explicit untrusted authentication evidence, stable evidence IDs,
HTML text sanitization and bounded body truncation. Failed/missing AI produces no
ai_assessment or final_verdict. Added qualitative severity/confidence and compact
new report UI with IOC search/pagination. See evidence-pipeline.md for limitations.

PostgreSQL/backend tests and all 44 frontend tests, lint and build pass. Updated an
old integration assertion that expected phishing without any model execution.
Semantic validation of arbitrary model prose, complete feature removal, queued VT
batches, dashboard failure aggregation and Windows portability are still pending.

## Feature removal increment

Removed live demo route/submission/UI/translations and mapping generation, report
sections, charts, schema and labels. Demo samples are test-only now. Historical
JSON remains in the database; obsolete mapping fields are omitted from read APIs.
Removed heuristic score accumulation, keyword judgments and Hybrid adjustment code.
Backend/PostgreSQL tests and 44 frontend tests, lint/build passed. One old UI test
asserting a removed badge was updated to require its absence and preserve reading.
