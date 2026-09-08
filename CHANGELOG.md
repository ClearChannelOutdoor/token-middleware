# Changelog

All notable changes to this project are documented here.

---

## [1.3.0] — 2026-04-01

### Added
- v4.local PASETO token support via `aidanwoods.dev/go-paseto`; token version is detected automatically from the `v4.local.` prefix before dispatch
- `tokenHandler_test.go` with 12 tests covering v4.local and v2.local tokens (valid, expired, scope allowed/denied, wrong key, query param)
- `CLAUDE.md` with build/test commands and architecture notes

### Changed
- `readme.md` updated to include v4 in the supported protocol versions table and `TokenHandler` description
- `BearTokenError` renamed to `BearerTokenError` (fixes typo; breaking for callers using the old name)
