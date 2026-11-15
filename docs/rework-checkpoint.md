# Verification status and known limitations

Branch `feature/full-rework`. This file states what was actually verified, how,
and what was not. "Mock" means the local stand-ins in
`backend/internal/mockproviders`; no request was sent to the real OpenAI or
VirusTotal services at any point.

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
