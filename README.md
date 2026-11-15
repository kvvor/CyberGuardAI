# CyberGuard AI

Security, made clear.

Authenticated AI settings, encrypted credential setup, execution statuses and the
evidence-based verdict policy are documented in [AI providers](docs/ai-providers.md).

The Go backend is in [backend/](backend/). It uses Gorilla/mux, PostgreSQL/pgx,
Argon2id password hashing, technical email evidence, consent-gated OpenAI Responses and VirusTotal hash reputation.

See [backend handoff](docs/backend-handoff.md) for local startup, implemented API
behavior, validation results, and outstanding work. The full MVP is still in
development. Docker work is deferred; PostgreSQL remains required for persistence.

From `backend/`, run `go build ./...`, `go test ./...`, and `go vet ./...`.
PostgreSQL integration tests require an isolated migrated `TEST_DATABASE_URL`.

- [OpenAPI contract](docs/openapi.yaml)
- [Architecture](docs/backend-architecture.md)
- [Security and residual risks](docs/security.md)
- [Detection evaluation procedure](docs/evaluation.md)
# Full-stack rework status

Work in progress on `feature/full-rework`. See [checkpoint](docs/rework-checkpoint.md)
for verified changes and remaining requirements. [VirusTotal integration](docs/virustotal.md)
adds migration 000003, encrypted per-user settings and separately authorized
attachment hash lookups. Apply all migrations before starting the updated backend.

Windows installation and startup: [Russian guide](docs/local-windows.md).
