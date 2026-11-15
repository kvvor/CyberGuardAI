# AI providers and hybrid policy v2

Only OpenAI is implemented. Gemini and Claude are extension targets, not advertised
connections. The providers package defines an assessment adapter boundary.

## Local configuration

Run `scripts/initialize-provider-key.ps1` once. It writes a random 32-byte base64
`PROVIDER_MASTER_KEY` to ignored `.env.local`. `scripts/backend.ps1` loads that key.
Protect and securely back up this file; replacing the key makes existing provider
credentials unreadable. Direct `go run` requires the same environment variable.

Provider keys use AES-256-GCM, random per-write nonces, and associated data binding
the ciphertext to the user ID, provider, and format version. PostgreSQL contains
only ciphertext. API responses include has_credential, never the key or ciphertext.
Deletion removes the ciphertext but does not erase database backups or WAL.

Authenticated routes (mutations require Origin and X-CSRF-Token):

- GET /api/v1/settings/ai-provider: metadata and last successful test.
- POST /api/v1/settings/ai-provider: provider=openai, model, enabled, api_key.
  Omitted/empty api_key preserves the saved key. Changes invalidate test status.
- POST /api/v1/settings/ai-provider/test: explicit model metadata request.
- DELETE /api/v1/settings/ai-provider: remove credentials and disable AI.

The metadata test sends no email and performs no inference or token generation.
It verifies credential/model metadata access, not Responses compatibility, available
quota, or detection quality. Only an actual successful metadata request yields
credential_validated; saving a key yields untested. Inference is billed according
to the configured provider/model and requires explicit per-analysis consent.

Environment fallback requires OPENAI_OPERATOR_FALLBACK_ENABLED=true together with
OPENAI_API_KEY and OPENAI_MODEL. This operator-funded configuration is shared with
authenticated users who have never created settings. A user's own settings always
take precedence, even when disabled or missing credentials. Removing credentials
keeps a disabled record, preventing fallback from silently reactivating AI.

## Execution and errors

JSON analysis requests accept ai_requested and external_processing_consent. For
older clients, consent also implies a request when ai_requested is omitted.
Multipart uses literal true fields; consent implies request for compatibility.
No email leaves the server without consent. Demo samples never call a provider.

ai_execution records requested, consent, configured, provider, model, source,
status, failure_code, static_verdict, deterministic_risk_score, ai_proposed_verdict,
final_verdict and influence_code. Existing report.risk_score is the final hybrid
score; ai_execution.deterministic_risk_score is the unchanged static score.
The synchronous API returns terminal status; it does not emit a running response.
Stored older reports may lack the new fields. Token usage is in ai_assessment.usage.

Stable codes include PROVIDER_NOT_CONFIGURED, PROVIDER_INVALID_CREDENTIALS,
PROVIDER_INSUFFICIENT_QUOTA, PROVIDER_UNSUPPORTED_MODEL, PROVIDER_RATE_LIMITED,
PROVIDER_NETWORK_FAILURE, PROVIDER_TIMEOUT, PROVIDER_INVALID_OUTPUT,
PROVIDER_ENCRYPTION_UNAVAILABLE, PROVIDER_CREDENTIAL_INVALID and AI_CONSENT_REQUIRED.
Failure retains static results and is never reported as successful AI execution.

## Decision policy

Model output cannot supply a risk score. Up to eight contextual observations must
quote 8–512 exact characters from submitted subject, plain text or HTML. Fabricated
quotes reject the assessment. Quote verification proves provenance, not the model's
interpretation. Such findings are explicitly model observations with unverified
interpretation, not verified attacks.

Each unique harmful contextual type contributes 30 points at high confidence,
15 at medium, zero at low; combined contextual contribution is capped at 60.
Static risk is never reduced. Final risk is capped at 100. Scores >=60 mean phishing;
20–59 mean suspicious. Levels are low <20, medium 20–44, high 45–69, critical >=70.
A legitimate verdict requires a model legitimate proposal, high-confidence benign
context quoting real content, zero static risk, sender and headers, no parser
warnings and no attachments. Otherwise low-risk results remain inconclusive.
These are heuristic criteria, not calibrated probabilities or safety guarantees.

## URLs and reports

Safe Links are decoded offline with a four-layer limit and IDN normalization.
Only actual decoded destinations receive URL checks. Length alone adds no risk.
Security wrappers confer no trust. Original and normalized URLs are retained;
resources and tracking-like resource paths are distinguished from actionable links.
IOCs are capped at 512, static findings at 128, contextual observations at eight.
IOC presence alone does not imply maliciousness. No URL is fetched.

top_findings contains up to five findings for concise display; the full report and
IOCs remain available for advanced review and exports. Narratives support en/ru/kk;
source evidence is never translated. Generic static guidance remains conservative.

Tests use synthetic keys, mocked HTTP providers, and cyberguard_test. No billed
live inference has been performed. Broader labeled-corpus evaluation is still
needed; these regressions do not establish a production false-positive rate.
