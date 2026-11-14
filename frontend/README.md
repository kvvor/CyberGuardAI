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

Contract source: ../docs/openapi.yaml and backend-handoff.md. Cookie credentials are included. Setup sessions cannot access application routes. /auth/me PASSWORD_CHANGE_REQUIRED recovers setup-only state, and the readable cyberguard_csrf cookie supplies CSRF after reload. Password changes invalidate sessions and return to login. Network errors remain explicit errors.

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
