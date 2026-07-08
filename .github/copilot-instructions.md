# Copilot instructions for `iitkgp-erp-login-go`

A Go **library** (package `iitkgp_erp_login`, module `github.com/metakgp/iitkgp-erp-login-go`) that automates the login workflow for the IIT Kharagpur ERP. It exposes a single public entry point and manages sessions, credentials, and email-OTP retrieval. This repo (`chrisrex007/...`) is a fork; upstream is `metakgp/iitkgp-erp-login-go`.

## Build / test / lint

There is no `main` package and no test suite yet. Standard Go tooling applies from the repo root:

- `go mod download` — fetch dependencies.
- `go build ./...` — compile the package.
- `go vet ./...` — static checks.
- `gofmt -l .` / `gofmt -w .` — check / apply formatting.
- Tests, if added: `go test ./...` (full suite) or `go test -run TestName ./...` (single test).

To exercise the library manually, create a throwaway `cmd/main.go` that calls `erp.ERPSession()` — this path is `.gitignore`d for exactly this purpose. Run it from a directory containing the config files below (they are read relative to the current working directory, not the source tree).

## Architecture (how the files fit together)

Only `ERPSession() (*http.Client, string, error)` in `iitkgp_erp_login.go` is exported. It orchestrates the full flow across the four files:

- `endpoints.go` — all ERP URL constants (login, secret question, OTP, homepage). The OTP endpoint is literally `getEmilOTP.htm` (ERP's typo, not ours).
- `iitkgp_erp_login.go` — the core flow: reuse a cached session → gather credentials → (OTP, only when `isOTPRequired()`) → POST login → extract the `ssoToken` from the HTML via `ssoTokenRegex` → seed the cookie jar. Returns a ready-to-use `*http.Client`, the token string, and an `error`.
- `read_mail.go` — OTP handling. `requestOTP` asks ERP to email an OTP; `fetchOTP` then either scrapes it from Gmail via the OAuth2/Gmail API (when `client_secret.json` or `.token` exists) or prompts the user to type it in. `extractMessageBody` recurses into multipart parts to find the body.
- `utils.go` — shared helpers: `fileExists`, `randomState`, and `generateToken` (the OAuth2 loopback flow).

**Config-file-driven behavior.** The flow branches on the *presence* of files in the working directory, via `fileExists(...)`:
- `.session` — cached ssoToken; when present and still valid, login is skipped entirely.
- `erpcreds.json` — roll number, password, and a `answers` map keyed by the security-question text (the fetched question is `TrimSpace`d before lookup); enables non-interactive login. Falls back to interactive terminal prompts when absent.
- `client_secret.json` + `.token` — Google OAuth client + cached token; enable automatic OTP retrieval from Gmail instead of manual entry.

**OAuth loopback.** `generateToken` opens the auth URL in a browser and serves a callback on `:7007` (`redirectURL = http://localhost:7007`) via a **local** `http.NewServeMux` (never the global `DefaultServeMux`), passing the result back over a channel and gracefully calling `server.Shutdown` when done.

## Key conventions (project-specific, not obvious)

- **Idiomatic Go, errors returned not fatal.** Helpers return `error`; `ERPSession` propagates them (there is no `log.Fatal`/`check_error` anymore). When adding code, thread errors up rather than crashing. Identifiers are idiomatic `MixedCaps` (`userID`, `getSecretQuestion`, `emailOTP`) — *except* the exported endpoint constants (`HOMEPAGE_URL`, `LOGIN_URL`, …), which keep their `UPPER_SNAKE` names because they are the documented public API used by consumers.
- **Session check by body length.** `isSessionAlive` reads the response body and treats `len(body) == 4145` as the logged-out homepage (invalid session). Uses the decoded body length, not `res.ContentLength`, so it works with chunked responses. If ERP changes that page, update the constant.
- **ssoToken extraction.** `extractSSOToken` uses `ssoTokenRegex` (`ssoToken=[^"'\s&]+`) and returns an error when no token is found (a failed login no longer panics). `strings.TrimPrefix(ssoToken, "ssoToken=")` yields the cookie value.
- **OTP gated by network.** `isOTPRequired()` pings `iitkgp.ac.in`; OTP is only requested when required, and the ping failing is treated as "OTP required" (fail-safe).
- **Hardcoded external assumptions.** The Gmail search query (`from:erpkgp@adm.iitkgp.ac.in is:unread subject: otp`) and package-level `const logging = true` are baked in; the OAuth `state` is now a random hex string from `randomState()` (`crypto/rand`).
- **Secret files land in the CWD.** `.session` and `.token` are written to the current working directory (mode `0600`), so behavior depends on where the consuming binary runs.
