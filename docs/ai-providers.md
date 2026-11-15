# Provider configuration

See [evidence pipeline](evidence-pipeline.md) for the current analysis lifecycle and limitations, [VirusTotal](virustotal.md) for hash-only lookup and licensing, [OpenAPI](openapi.yaml) for endpoints, and [Windows setup](local-windows.md) for configuration.

The Go backend uses Gorilla/mux, pgx/PostgreSQL, encrypted per-user provider settings and versioned migrations. Authentication, session-bound CSRF, exact Origin checking, optional registration and owner-scoped history remain in place. Uploaded email content is untrusted data. External provider operations require independent consent. Validated OpenAI proposals determine live verdicts; failed operations retain evidence without a fabricated assessment.
