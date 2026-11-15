# Live evidence pipeline (version 3)

The live handler reuses existing EML/MSG parsing and IOC extraction, performs
separately authorized VirusTotal hash lookup, and prepares selected evidence.
Legacy keyword judgments, scores and attack mappings are excluded from the model
input. A validated OpenAI proposal determines the final verdict directly; Hybrid
is no longer called by the live API. Legacy code remains pending removal.

OpenAI Responses uses strict JSON schema, no tools, store=false, no reasoning
parameter, a 45-second request deadline and bounded responses. The existing
schema now includes qualitative severity and confidence. Settings suggest
gpt-4.1-mini/gpt-4.1 and allow a model identifier; metadata tests check access,
not inference compatibility. See the official [structured output guide](https://developers.openai.com/api/docs/guides/structured-outputs)
and [model capabilities](https://developers.openai.com/api/docs/models/gpt-4.1-mini).

Evidence IDs identify sender, subject, technical observations, IOCs, attachments,
reputation and selected routing/authentication headers. Exact contextual quotes
are checked against the transmitted normalized text. Unknown evidence references,
invalid categories and unsupported ungrounded verdicts are rejected. Schema and
reference checking does not prove that every free-text model interpretation is
correct: semantic authentication/reputation claims still require stronger typed
validation. This remains a release blocker for the full requested scope.

Authentication-Results is reported, untrusted evidence. No receiver trust anchor,
SPF reconstruction, DKIM cryptographic verification or independent DMARC alignment
is claimed. Received values retain order without attributing an origin computer.
Missing headers are unavailable, including pasted body text containing auth terms.
More complete Received-SPF/DKIM/MSG parsing remains future work.

HTML-derived text omits scripts/styles; URLs are never visited. Bodies truncate
at 24,000 bytes each on UTF-8 boundaries with a limitation. Technical evidence
has per-field/count limits; serialized input over 128,000 bytes fails explicitly.
Raw body/header fields are removed from persisted email metadata. Evidence
snippets and validated quotes are retained and may contain sensitive content.

If AI did not complete, analysis status is partial, ai_assessment is absent and
ai_execution.final_verdict is empty. The existing SQL verdict remains inconclusive
as a compatibility placeholder, never an AI conclusion. API consumers must check
status and ai_assessment. New report screens label this as incomplete. Historical
scoring fields remain readable. Risk score is omitted when zero and is never a
probability. SQL/dashboard aggregation of incomplete and legacy reports still
needs a dedicated migration and revised statistics.

New report UI includes qualitative verdict, grounded findings, recommendations,
collapsible authentication/evidence and searchable paginated IOC display. New PDF
reports omit numerical scores and include authentication and supporting evidence.
