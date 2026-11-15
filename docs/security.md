# Security and residual risks

Per-user AI credentials are AES-256-GCM encrypted with user/provider/version-bound
associated data. PROVIDER_MASTER_KEY resides in the server environment or ignored
local configuration. Provider endpoints require full authentication and CSRF on
mutations. Metadata connection tests send no email or inference requests. Read
[AI provider policy](ai-providers.md) for isolation and explicit operator fallback.
Contextual quotes are checked against input; their interpretation is not independently
verified. Validated model proposals determine live verdicts; heuristic scores are not authoritative. No analysis URL is fetched.

Passwords use salted Argon2id with 19 MiB, two passes, one lane, and 32-byte
outputs, following the OWASP baseline:
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
Temporary credentials and sessions have 256 random bits. PostgreSQL holds only
credential hashes and SHA-256 token hashes. CSRF tokens are domain-separated
derivatives of random session tokens and checked against stored hashes.

Temporary redemption, activation, reset, and disable use transactions.
Authentication is rate-limited by directly connected IP. Proxy headers are not
trusted. Account-based and deployment-wide limits remain pending hardening.

MIME depth, decoded bytes, attachment count, part count, upload size and MSG reads
are bounded. Attachments are never executed. Message URLs are never fetched.
MSG uses gomsg/mscfb; bounded reads are not OS process isolation. More adversarial
OLE tests and process isolation should precede public exposure.

OpenAI requires explicit consent, uses store:false, strict structured output, no
tools, evidence-ID validation, and bounded score adjustments. Prompt injection
cannot be eliminated by prompting. Official API reference:
https://developers.openai.com/api/docs/guides/structured-outputs

Stored evidence can contain private data. Row deletion does not erase backups,
WAL, snapshots or SSD history. RETENTION_DAYS enables optional hourly cleanup; deletion does not erase backups.
Before exposure beyond localhost, finish integration/security testing, require
HTTPS and Secure cookies, review proxy trust and global resource limits, and
complete the hardening tracked in backend-handoff.md.
