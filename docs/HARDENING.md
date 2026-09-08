# Site hardening headers

Evidence file for the Contributor Best Practices Badge criteria `hardened_site`
and `sites_https`. Headers were verified live with `curl -sI` on the date below.

Verified: 2026-09-08.

## Project website — https://dialga-cmd.github.io/gun101-gkp/

The site is static HTML built from `docs/` (see `.github/workflows/pages.yml`).
It ships an explicit, nonpermissive Content-Security-Policy and Referrer-Policy
in `docs/index.html`:

- `Content-Security-Policy`:
  `default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:;
  connect-src 'self'; base-uri 'self'; form-action 'none'; font-src 'none';
  frame-ancestors 'none'; object-src 'none'`
  (no scripts, forms, or frames are allowed).
- `Referrer-Policy`: `strict-origin-when-cross-origin`.
- **Transport security, content-type sniffing, and clickjacking protection are
  provided by the GitHub edge platform** that serves `*.github.io`: GitHub
  applies its platform hardening headers on every response, including a strict
  `Content-Security-Policy: default-src 'none'; ...` and HTTPS-only (HSTS) for
  `github.io` domains.

The domain is HTTPS-only (`sites_https`); there is no HTTP entry point.

## Repository (web UI) — https://github.com/dialga-cmd/gun101-gkp

GitHub sends nonpermissive hardening headers on all `github.com` responses,
verified values include:

- `Strict-Transport-Security: max-age=31536000; includeSubdomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: deny`
- `Referrer-Policy: no-referrer-when-downgrade`
- `Content-Security-Policy: default-src 'none'; base-uri 'self'; form-action
  'self' ...; frame-ancestors 'none'; upgrade-insecure-requests; ...`

## Download site — https://pypi.org/project/gun101-gkp/

PyPI sends the following nonpermissive hardening headers (verified):

- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: deny`
- `Permissions-Policy:` (denies camera, geolocation, microphone, USB, and other
  sensitive features)

## How to re-verify

```bash
curl -sI https://dialga-cmd.github.io/gun101-gkp/ | head -30
curl -sI https://github.com/dialga-cmd/gun101-gkp | grep -iE "strict-transport|content-security|content-type-options|x-frame|referrer"
curl -sI https://pypi.org/project/gun101-gkp/ | grep -iE "strict-transport|content-security|content-type-options|x-frame|permissions"
```