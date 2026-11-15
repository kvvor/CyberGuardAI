# VirusTotal attachment reputation

Apply migration 000003 before running the updated backend. It extends the existing
provider table to a `(user_id, provider)` key and preserves OpenAI ciphertext.
AES-GCM authenticated data binds credentials to both user and provider. Never
change PROVIDER_MASTER_KEY without decrypting/re-encrypting saved credentials or
explicitly removing and re-entering them. Back up the key separately and securely.

Settings exposes OpenAI and VirusTotal save/replace/delete/enable/test operations.
GET responses contain configuration metadata only. Empty API key input preserves
the current credential. Requests use existing session/Origin/CSRF protections.

VirusTotal endpoints: GET/POST/DELETE `/api/v1/settings/virustotal`,
POST `/api/v1/settings/virustotal/test`. Testing explicitly sends the public hash
of an empty file; it consumes a lookup, never sends an email, and does not upload.

Analysis JSON and multipart requests accept `virustotal_consent` (default false),
independent of `external_processing_consent` for OpenAI. Attachments are SHA-256
hashed by the existing parsers. Hash results appear in
`report.attachment_reputation`, before OpenAI assessment and in stored JSON.
No raw attachment data is accepted by the VirusTotal client.

The client uses [GET /api/v3/files/{sha256}](https://docs.virustotal.com/reference/file-info)
with x-apikey, a 15-second timeout, a 2 MiB response limit, no redirects and no
automatic retries. Hashes are deduplicated within each analysis. Unknown hashes
remain unknown; zero detections never means safe. Provider dates are retained.

Conservative per-user quotas (15 seconds between requests, 500/day UTC) persist
in PostgreSQL and survive credential replacement. Excess distinct attachment
lookups return rate_limited rather than silently claiming a check ran. This
currently means a batch may only check its first distinct hash. A future queued
worker is needed to complete larger batches without exceeding HTTP deadlines.
Use of the same key in other applications can also exhaust provider quota.

The [Public API terms](https://docs.virustotal.com/reference/public-vs-premium-api)
prohibit commercial products/services and business workflows that do not
contribute new files. A hash-only business workflow may therefore require a
suitable paid license. CyberGuard never uploads files to satisfy these terms.

Tests use mock HTTP servers; no live credentials or provider connectivity have
been verified. Hash lookup consent and settings do not yet replace the legacy
final classification engine; see rework-checkpoint.md for unfinished scope.
