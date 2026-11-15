# CyberGuard AI frontend

React/JavaScript + Vite frontend for the documented Go API. All runtime API calls use the real backend; there is no production mock fallback. Tests mock fetch in isolation.

## Run on Windows

Start the backend using ../docs/local-windows.md, then:

```powershell
Set-Location -LiteralPath "D:\AI\CyberGuardAI-frontend\frontend" -ErrorAction Stop
npm.cmd ci
npm.cmd run dev
```

Open http://localhost:3000. Use localhost consistently. Vite forwards /api to http://127.0.0.1:8080 while preserving Origin. npm.cmd avoids the Windows PowerShell script execution policy restriction; ordinary npm commands also work in cmd.exe.

```powershell
npm.cmd run test
npm.cmd run lint
npm.cmd run build
```

Production hosting must serve dist with SPA fallback and reverse proxy /api to Go on the same origin. Configure the backend allowed origin and secure HTTPS cookies for that deployment. No hosting or deployment was performed.

## Implementation map

- src/App.jsx: routes, guards, shell, settings, error boundary.
- src/contexts/Auth.jsx: session recovery, setup state, logout.
- src/services/api.js: cookie requests, memory/cookie CSRF, timeout/cancellation, stable errors, report blobs.
- src/pages/Auth.jsx: login, activation, password change.
- src/pages/Analyzer.jsx: EML/MSG, pasted text, backend demo samples, explicit external AI consent.
- src/pages/Dashboard.jsx: charts, aggregates, recent reports, server-filtered history and pagination.
- src/pages/Details.jsx: verdict, heuristic risk, evidence, IOCs, MITRE, attachments, AI state, recommendations, exports, confirmed deletion.
- src/pages/Help.jsx: twelve localized help topics.
- src/components/common.jsx: resource/loading/error states and preferences.
- src/components/ui/button.jsx: shadcn-style Radix Slot/CVA button, integrated in authentication forms; components.json defines JavaScript configuration.
- src/i18n/: EN/RU/KK interface dictionaries and help. Original evidence, backend technical codes, sample names and technique names remain verbatim.
- src/styles.css: dark/light tokens, responsive shell and reduced-motion styles.
- src/test/: 24 API and component tests.

## API and security

Contract source: ../docs/openapi.yaml. Cookie credentials are included. Setup sessions cannot access application routes. /auth/me PASSWORD_CHANGE_REQUIRED recovers setup-only state, and the readable cyberguard_csrf cookie supplies CSRF after reload. Password changes invalidate sessions and return to login. Network errors remain explicit errors.

Uploads are checked against the public max_email_size, with the documented 10 MiB fallback. File extensions are EML/MSG only. External processing consent defaults to false. Demo requests use source_type=demo and backend-provided sample IDs. Suspicious URLs render only as text. No email HTML rendering, remote email images, attachment execution, stored passwords, session identifiers or API keys.

## Verification performed

- npm.cmd run test: 24 passed.
- npm.cmd run lint: passed.
- npm.cmd run build: passed; main bundle size warning remains (approximately 574 kB minified, 188 kB gzip); charts are loaded separately.
- Dev server started successfully on port 3000; HTTP 200 verified.
- Real backend /health returned ok.
- Through Vite, /config/public returned en/ru/kk, 10485760 bytes, public_signup=false.
- Through Vite, unauthenticated /auth/me returned 401.
- No authenticated live lifecycle or paid OpenAI call was performed. Component tests are not end-to-end verification.

## Manual browser checklist (outstanding)

No browser automation tool was available in this session. Use a CLI-provisioned test account; do not put credentials in source or chat.

1. Open /settings while signed out; verify redirect to login, keyboard labels, password visibility and error feedback.
2. Login with a temporary password; verify activation, refresh recovery and rejection of protected routes before activation. Let setup expire and verify operator-reset guidance.
3. Activate with a Unicode passphrase; verify dashboard. Refresh and confirm regular session recovery.
4. Submit an EML, a MSG and pasted text with consent unchecked. Check real saved reports, partial flags and unavailable AI state. Reject an oversized file and an unsupported extension.
5. Select all six synthetic samples; verify labels and separation from live dashboard/history. Do not enable paid external AI processing unless separately intended.
6. Inspect metadata, score, findings, nonclickable IOCs, copy/defang, MITRE evidence, attachments and limitations. Confirm malicious-looking HTML remains plain text.
7. Export PDF/JSON in each language and inspect actual downloaded files.
8. Search/filter/sort/date-filter history, move through pages, cancel deletion, then confirm a test report deletion.
9. Change password; verify reauthentication and invalidation of prior sessions. Verify logout and expired-session redirects.
10. Check EN/RU/KK, all themes, narrow viewport navigation, keyboard focus, dialog Escape/focus return, reduced motion and chart readability.
11. Stop the backend; verify retry errors instead of demo fallback. Restart and retry.

## Remaining gaps

Authenticated live browser integration, visual/accessibility review, and complete native-language review remain unverified. Backend technical finding codes and free-text parser/AI evidence are shown verbatim; human-friendly localization of the entire backend finding vocabulary is not yet implemented. The top bar has preferences; account information/logout live in the sidebar rather than a separate account-menu popover. Notifications use inline accessible status/error feedback rather than a toast system. Sidebar animation is CSS-based. These gaps mean the full requested definition of done has not yet been verified.

The backend schema does not provide a dedicated CC field, per-attachment warnings field, or profile-edit endpoint. The frontend does not invent these fields or endpoints. Attachment warnings are available only through overall findings/parser warnings. No backend source was modified.

## Website registration integration

Implemented against the updated OpenAPI and handoff in backend commit `c1abb68`, read directly using `git show`. The docs/backend source in this frontend worktree remain at the earlier checkpoint; no backend files or branches were merged or modified.

- `/register` submits only display_name, email, password and confirm_password to POST /api/v1/auth/register. Public registration requires Origin, not a session CSRF token.
- Public config must return public_signup=true. Otherwise the login signup link is hidden and direct registration displays a disabled message. Config failures offer retry and never enable signup by default.
- The backend returns identical REGISTRATION_ACCEPTED acknowledgments for new and duplicate accounts. The localized success notice accurately says the request was accepted and directs existing users to their existing password. Registration never establishes a session.
- Passwords remain in form/request memory only. Redirect state contains only a boolean success flag. CLI activation remains unchanged.
- EN/RU/KK includes validation and registration errors. Server-disabled registration, rate limits, invalid input and network failures are handled.

Backend operator: launch the registration-capable backend with `$env:PUBLIC_REGISTRATION_ENABLED="true"` in its process environment. The flag defaults to false and requires a backend restart. Do not run the older backend sources in this frontend worktree expecting registration support.

Validation: 36 automated tests pass, lint passes, build passes (existing bundle-size warning). The running backend public configuration still reports false, so live account creation/login was not attempted or claimed verified. No browser automation is available. For manual verification after enabling: open login, follow Create Account, register a fresh email, verify acknowledgment on login, sign in; repeat registration with that email and verify the same acknowledgment without changing its existing password. Verify CLI temporary-password login still requires activation, then check disabled registration and RU/KK rendering.
