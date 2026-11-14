# CyberGuard AI backend architecture

The backend is a Go modular monolith using Gorilla/mux, PostgreSQL through pgx,
and versioned SQL migrations. The CLI provisions accounts; no public signup or
administrator HTTP API is exposed.

## Trust boundaries

HTTP handlers validate bounded input and delegate to services. Repository methods
take the authenticated owner ID for every analysis operation. Email parsing,
static detection, scoring, and report rendering remain independently testable.
Original messages and attachment binaries are transient by default.

## Authentication lifecycle

Provisioning creates a pending account with a random, Argon2id-hashed temporary
credential expiring after 24 hours. Login atomically consumes that credential and
creates a restricted 15-minute setup session. Activation consumes the setup
session, replaces the password hash, and creates a fresh regular session.
Expired setup requires CLI reset. Reset and disable revoke every session.

Session cookies hold random opaque tokens; PostgreSQL stores token hashes only.
Regular sessions enforce idle and absolute expiration. Authenticated mutations
require a session-bound CSRF token and an allowed Origin. Password change revokes
existing sessions. Passwords, session tokens, and email bodies must not be logged.

## Analysis lifecycle

Authenticated input is parsed into one normalized email model. Static rules,
attachment inspection, and IOC extraction run without network access. Explicit
consent is required before sending bounded text and metadata to OpenAI Responses.
Strict structured output is validated against the available evidence. A versioned
heuristic assigns the final score; unavailable AI produces a partial result.

Persisted reports carry an owner, mode, evidence, limitations, and scoring version.
History, exports, and dashboard aggregations enforce ownership in SQL. Synthetic
demo records are excluded from live statistics by default.

## Implementation status

This document defines the intended architecture. Implementation and validation
status are tracked in backend-handoff.md; design statements are not test results.
