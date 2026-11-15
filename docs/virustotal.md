# VirusTotal attachment reputation

CyberGuard looks up the **SHA-256 hash** of each attachment with
`GET https://www.virustotal.com/api/v3/files/{sha256}` and the `x-apikey`
header ([file report reference](https://docs.virustotal.com/reference/file-info)).

What never happens: no file upload, no attachment bytes sent anywhere, no
attachment executed, no URL from the email opened or submitted.

## Consent and configuration

Lookups run only when the user has saved and enabled a VirusTotal key **and**
ticks the VirusTotal consent box for that analysis. This consent is separate
from the OpenAI consent. Without it no request is made and each attachment is
reported as `not_requested`.

## Result per attachment

`sha256`, `status`, `source` ("VirusTotal API v3"), `statistics` (malicious,
suspicious, harmless, undetected, timeout, failure, type-unsupported),
up to 32 detection labels, `last_analysis_at`, `checked_at`.

| Status | Meaning |
|---|---|
| `completed` | report received |
| `not_found` | HTTP 404: the hash is unknown to VirusTotal. **Not evidence of safety.** |
| `authentication_failed` / `access_forbidden` | 401 / 403 |
| `rate_limited` | 429 from VirusTotal (rate or quota) |
| `deferred_local_limit` | not sent: CyberGuard's own allowance was used up |
| `timeout`, `network_error`, `provider_error` | no usable answer |
| `not_requested`, `not_configured` | no consent / no key |

Zero detections do not prove a file is safe either. The interface and reports
say so, and the assessment model may not describe attachments as free of
detections unless every attachment has a completed lookup.

The overall `virustotal_status` is `completed`, `partial` (some hashes
answered), `skipped_no_attachments`, or the first failure.

## Quotas and batches

CyberGuard keeps a per-user allowance in PostgreSQL: a sliding 60-second window
and a UTC daily counter. Defaults are 4 per minute and 500 per day, the Public
API allowance. `VIRUSTOTAL_REQUESTS_PER_MINUTE` and
`VIRUSTOTAL_REQUESTS_PER_DAY` raise them for a licence that permits it.
Replacing or deleting the key does not reset the counters. The connection test
uses one request.

Within one analysis identical hashes are requested once, lookups are serial,
there are no automatic retries, and the batch has a 45-second budget. When the
allowance is used up, the remaining distinct hashes are marked
`deferred_local_limit`. They are not silently dropped: the report shows them
and offers **"Check the remaining hashes now"** (`POST
/analyses/{id}/virustotal`), which requests only unanswered hashes once the
window is free. If a verdict already exists it is kept and the report is marked
`REPUTATION_UPDATED_AFTER_ASSESSMENT`, because the verdict was formed without
the new results. There is no background worker; a message with more than four
distinct attachments therefore needs one manual re-check per additional four.

The same key used by other tools also consumes VirusTotal's own quota; in that
case VirusTotal answers 429 and the status is `rate_limited`.

## Licence limits

VirusTotal's [Public API](https://docs.virustotal.com/reference/public-vs-premium-api)
is rate limited and, under its terms, must not be used in commercial products
or services or in business workflows that do not contribute new files.
CyberGuard only performs lookups and never uploads, so use inside an
organisation may require a Premium licence. This is a summary of the published
terms, not legal advice; check the current terms for your situation.

## Verification status

All behaviour above is covered by automated tests against a local mock server
(status mapping, malformed and oversized responses, redirects, timeouts,
duplicate hashes, allowance, deferred re-check). **No request has been made to
the real VirusTotal service**, so live key acceptance and real response shapes
remain to be confirmed with an authorised key.
