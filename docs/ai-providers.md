# Provider settings and OpenAI

Each user configures their own keys in **Settings**. Keys are encrypted with
AES-256-GCM under `PROVIDER_MASTER_KEY`; the associated data binds every
ciphertext to its user and provider. A browser never receives a saved key.

## API

| Request | Purpose |
|---|---|
| `GET /settings/ai-provider`, `GET /settings/virustotal` | metadata only: model, enabled, has_credential, connection_status, last_success_at |
| `POST …` `{provider, model, api_key, enabled}` | save; an empty `api_key` keeps the saved key |
| `DELETE …` | remove the key |
| `POST …/test` | connection test |
| `GET /settings/ai-provider/models` | models available to the saved key |
| `POST /settings/ai-provider/models` `{api_key}` | the same for a key that is not saved yet (not stored) |

Keys are trimmed; a key with inner whitespace or non-ASCII characters is
rejected (`PROVIDER_KEY_MALFORMED`). The first save requires a key
(`PROVIDER_KEY_REQUIRED`). Provider operations have their own rate limit
(30 per minute per address) separate from sign-in.

## Models

No model list is built into the application. The list is read from
`GET /v1/models` with the user's key; embedding, audio, image and similar
non-text families are hidden from the list (a display filter only). Any model
ID can be typed. Whether a model supports strict structured output through the
Responses API is decided by OpenAI at request time; an unsuitable model yields
`unsupported_model` with no verdict. The selected model is stored per user and
used for every analysis.

The connection test reads `GET /v1/models/{id}`: it checks the key and access
to the model, runs no inference and costs nothing.

## Errors

Every failure has a specific code and a localised message.

| Code | HTTP | Meaning |
|---|---|---|
| `DATABASE_SCHEMA_OUTDATED` | 503 | migrations not applied; run `scripts\setup.ps1` |
| `DATABASE_UNAVAILABLE` | 503 | PostgreSQL unreachable |
| `PROVIDER_ENCRYPTION_UNAVAILABLE` | 503 | `PROVIDER_MASTER_KEY` missing or malformed |
| `PROVIDER_CREDENTIAL_UNREADABLE` | 409 | master key changed since the key was saved |
| `PROVIDER_NOT_CONFIGURED`, `PROVIDER_DISABLED` | 409 | no key / switched off |
| `PROVIDER_KEY_REQUIRED`, `PROVIDER_KEY_MALFORMED`, `PROVIDER_MODEL_INVALID` | 400 | input problems |
| `CSRF_INVALID`, `ORIGIN_INVALID` | 403 | reload, or open the site with the configured origin |
| `UNAUTHENTICATED` | 401 | session expired |
| `RATE_LIMITED` | 429 | too many attempts |

Connection tests and model listing answer `200` with
`{success:false, failure_code}` for provider-side failures:
`PROVIDER_INVALID_CREDENTIALS`, `PROVIDER_ACCESS_DENIED`,
`PROVIDER_INSUFFICIENT_QUOTA`, `PROVIDER_RATE_LIMITED`,
`PROVIDER_UNSUPPORTED_MODEL`, `PROVIDER_TIMEOUT`, `PROVIDER_NETWORK_FAILURE`,
`PROVIDER_ERROR`.

Unexpected storage errors are logged on the server with the request ID,
SQLSTATE and message (never row contents, keys or email text) and returned as
`INTERNAL_ERROR` with that request ID.

### The "server could not complete the request" defect

Cause: the application database was still at migration `000002`, while saving a
key uses `ON CONFLICT (user_id, provider)`, which needs the key created by
`000003`. PostgreSQL answered `42P10`; the handler discarded the error and
returned a bare `INTERNAL_ERROR`. `/health` only pinged the database, so it
stayed green, and the test database had been migrated, so tests passed.

Now: the backend refuses to start against a schema that does not match, the
start script applies migrations first, `/health` reports the schema state, and
schema errors reach the user as `DATABASE_SCHEMA_OUTDATED` with the fix.
`TestOutdatedSchemaIsReportedNotInternalError` reproduces the situation.

## Request behaviour

- timeout 90 seconds per analysis including retries; the HTTP handler allows
  170 seconds for the whole analysis;
- up to two retries for rate limiting and provider 5xx, honouring
  `Retry-After`; credential, quota, model and validation failures are never
  retried;
- redirects are not followed (the bearer key stays on the configured host);
- `max_output_tokens` 12 000; a truncated answer is discarded.

## Prompt injection

Email content is untrusted. It travels only inside the JSON input document;
the instructions are a fixed constant. The model has no tools, so text in an
email cannot trigger requests, read files or change settings. Text addressed to
an automated analyser is itself recorded as evidence. Output validation bounds
the damage if a model is manipulated anyway: it cannot cite evidence that does
not exist, upgrade authentication results, call a detected attachment clean or
return a verdict without grounding. Prompting cannot make injection impossible;
a manipulated model could still choose a wrong verdict among the allowed ones
while citing real evidence.

## Operator options

`OPENAI_API_KEY`, `OPENAI_MODEL` and `OPENAI_OPERATOR_FALLBACK_ENABLED=true`
provide a shared key for accounts without their own. `OPENAI_BASE_URL` and
`VIRUSTOTAL_BASE_URL` point the backend at a gateway or at the local mocks.

## Testing without real keys

```powershell
# from backend\
go run ./cmd/mockproviders
```

Start the backend with `OPENAI_BASE_URL=http://127.0.0.1:18090/openai/v1` and
`VIRUSTOTAL_BASE_URL=http://127.0.0.1:18090/virustotal/api/v3`, then use the
keys printed by the mock (`mock-valid-key`, `mock-invalid-key`,
`mock-quota-key`, …) in Settings. The mock "assessment" is a fixed rule set for
exercising the pipeline. It is not a model and says nothing about accuracy.
