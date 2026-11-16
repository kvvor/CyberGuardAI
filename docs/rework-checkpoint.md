# Verification status and known limitations

This file states what was actually verified, how,
and what was not. "Mock" means the local stand-ins in
`backend/internal/mockproviders`; no request was sent to the real OpenAI or
VirusTotal services at any point.

## UI improvement round (branch `feature/ui-improvements`)

Baseline before this round: commit `8abd972`, kept as branch
`backup/before-ui-improvements` and annotated tag `backup-before-ui-improvements`.
`feature/full-rework` was not changed. No database migration was added; the
schema stays at version 4.

Changed in this round: two-level report (simple view and technical details),
categorical verdict indicator, removal of the contradictory-evidence section
from interface, PDF and JSON export, removal of the model-uncertainty section
from the PDF, per-method authentication parsing and display, tolerant header
decoding, separate display name and sending address, trilingual quote
explanations, link and attachment presentation, manual VirusTotal hash lookup,
file selection state, loading state, Settings layout, "Copy" label, favicon,
dashboard entry animation, qualified wording for legitimate verdicts.

Verified in this round:

| What | How |
|---|---|
| Backend | `go build`, `go vet`, `go test ./...` with `cyberguard_test`: 12 packages pass |
| Frontend | 120 component tests, `eslint`, production build (favicon present in `dist`) |
| Authentication mapping, header decoding, sender split, display-name observations, mailto, configuration profiles | `internal/detection/regression_test.go`, `internal/emailparser/headers_test.go` |
| Hash lookup endpoint, export without contradictory section, trilingual model text, pasted text without file name | `internal/api/presentation_test.go` (HTTP + PostgreSQL + mock) |

**Not verified in this round: the browser pass.** The isolated test instance
was started but the operating system stopped it for lack of memory before any
page was opened. The new interface has therefore been exercised by component
tests only, not in a real browser: visual layout, responsive behaviour, the
favicon in a tab, the animations and the PDF's appearance were not looked at.
The earlier browser pass (below) covered the previous interface.

Stored reports: analyses created before this round keep single-language quote
explanations and have no separate display name/address fields; the interface
falls back gracefully for both. New model responses must be trilingual, which
makes them slightly longer.

### Returning to the version before this round

Code (nothing is deleted; the new work stays on its own branch):

```powershell
git switch feature/full-rework          # or: git switch --detach backup-before-ui-improvements
```

Then restart backend and frontend. Because this round added no migration and
changed no stored data, the database works with both versions and needs no
restore. A backup taken before the round exists outside the repository at
`D:\AI\CyberGuardAI-db-backups\cyberguard-before-ui-improvements-20261116-083058.dump`
(PostgreSQL custom format, verified readable with `pg_restore --list`). To
restore it into an empty database, should that ever be wanted:

```powershell
# pg_restore.exe is in the bin folder of your PostgreSQL installation
createdb -U postgres cyberguard_restored
pg_restore --no-owner --dbname "postgres://USER:PASSWORD@localhost:5432/cyberguard_restored" "D:\AI\CyberGuardAI-db-backups\cyberguard-before-ui-improvements-20261116-083058.dump"
```

Restoring over the live database would discard analyses made since the backup;
restore into a separate database and switch `DATABASE_URL` instead.

## The Settings defect

"The server could not complete the request" when saving an API key was caused
by the application database being at migration 000002 while the code required
000003. Details and the fix are in
[ai-providers.md](ai-providers.md#the-server-could-not-complete-the-request-defect).
The situation is reproduced by `TestOutdatedSchemaIsReportedNotInternalError`.
The application database on the development machine is now at version 4.

## Verified

| Area | How |
|---|---|
| Go build, vet | `go build ./...`, `go vet ./...` |
| Backend unit tests | `go test ./...` (12 packages) |
| Backend with PostgreSQL | same with `TEST_DATABASE_URL` (isolated `cyberguard_test`, migrated to version 4) |
| Provider settings: save, reload, model list, test, replace, disable, remove, isolation, encryption at rest, all negative cases | `TestProviderSettingsWorkflow`, `TestMissingMasterKeyIsReported` (HTTP + PostgreSQL + mock) |
| Analysis pipeline: EML, MSG, paste, hashing, VirusTotal, evidence, OpenAI, validation, storage, reopen, history, dashboard, PDF, JSON | `TestAnalysisPipelineWithMockProviders` |
| Provider failures never produce a verdict | `TestProviderFailuresNeverProduceAVerdict` |
| VirusTotal duplicates, allowance, deferred re-check | `TestVirusTotalBatchesQuotaAndRecheck` |
| Historical reports readable, no attack-framework data returned, not counted as verdicts | `TestLegacyReportsStayReadable` |
| Sign-in, session persistence, password change, sign-out, registration switch | `TestAuthenticationFlow` |
| Model output validation, prompt-injection boundary, request shape | `internal/openai` tests |
| Evidence extraction and false-positive regressions | `internal/detection`, `internal/evaluation` tests |
| Parser robustness (nested MIME, encodings, limits, malformed input, MSG) | `internal/emailparser` tests |
| Frontend | 87 component tests, `eslint`, production build |
| Browser, real UI, isolated instance (test database + mocks) | register, sign in, session after reload, OpenAI and VirusTotal save / model list / test / replace with failing keys, EML upload with both consents, report, PDF and JSON export, incomplete report after a quota failure, history filter, dashboard counts, Russian and Kazakh, backend stopped |
| Windows scripts | syntax of all scripts; `backend.ps1 -Mode status`; `start-backend.ps1` (migrate, then serve); `setup.ps1` guard paths and `initialize-provider-key.ps1` from a folder with spaces; `psql.exe` discovery |
| OpenAPI document | parsed and validated by `TestOpenAPIContract` |

## Not verified

- **Live OpenAI**: key acceptance, the model list, and above all whether a
  given real model accepts the strict schema and how good its verdicts are.
  The request format follows the Responses API documentation but has only met
  the mock.
- **Live VirusTotal**: key acceptance and real response bodies.
- **Detection quality**: no precision/recall figures exist for any real model
  ([evaluation.md](evaluation.md)).
- **Fresh installation** from a ZIP on a separate clean Windows machine, and an
  interactive run of `setup-postgres.ps1` (needs the PostgreSQL administrator
  password). `setup.ps1` was not run to completion on the development machine
  because `npm ci` would have replaced dependencies under a running dev server.
- **Race detector** (`go test -race`): needs a C toolchain that is not
  installed here.
- **Manual accessibility and small-screen review**: layouts are responsive by
  CSS and controls are labelled, but no screen-reader or device testing was done.
- Real Outlook `.msg` files: tests use a synthetic container.

## Known limitations

- SPF, DKIM and DMARC are reported from headers, not verified. DKIM
  verification would need DNS lookups for attacker-chosen domains and was left
  out deliberately.
- Model prose is not fact-checked; only typed fields, references and quotes are.
- Model explanations are produced in English, Russian and Kazakh by the model;
  their translation quality depends on the model.
- VirusTotal batches above the per-minute allowance need a manual re-check;
  there is no background queue.
- Analysis is one synchronous request (up to 170 seconds). Progress shows the
  requested steps and elapsed time, not per-step completion.
- Sorting history by legacy score was removed from the UI; the API still
  accepts `risk_desc`/`risk_asc` for historical rows.
- The production frontend bundle is large (charting library); no code
  splitting beyond the dashboard.
- Rate limiting is in-memory and per address. See [security.md](security.md)
  before exposing the application beyond `localhost`.

No push and no merge to `main` have been made. No application data was deleted.
