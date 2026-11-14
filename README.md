# CyberGuard AI

Security, made clear.

The Go backend is in [backend/](backend/). It uses Gorilla/mux, PostgreSQL/pgx,
Argon2id sessions, static email analysis, and consent-gated OpenAI Responses.

See [backend handoff](docs/backend-handoff.md) for local startup, implemented API
behavior, validation results, and outstanding work. The full MVP is still in
development. Docker work is deferred; PostgreSQL remains required for persistence.

From `backend/`, run `go build ./...`, `go test ./...`, and `go vet ./...`.
PostgreSQL integration tests require an isolated migrated `TEST_DATABASE_URL`.

- [OpenAPI contract](docs/openapi.yaml)
- [Architecture](docs/backend-architecture.md)
- [Security and residual risks](docs/security.md)
- [Detection evaluation procedure](docs/evaluation.md)
