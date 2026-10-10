# PoC Labs

Local proof-of-concept and security lab collection. Each subdirectory is a self-contained lab; see that folder’s README for setup and usage.

| Lab | Path | Summary |
| --- | --- | --- |
| CVE-2026-1830 | [`cve-2026-1830-wordpress-lab`](./cve-2026-1830-wordpress-lab/) | WordPress Quick Playground ≤ 1.3.1 — unauthenticated RCE via upload |
| CVE-2026-3180 | [`cve-2026-3180-wordpress-lab`](./cve-2026-3180-wordpress-lab/) | WordPress Contest Gallery ≤ 28.1.4 — unauthenticated blind SQL injection |
| Nginx-Rift | [`Nginx-Rift`](./Nginx-Rift/) | NGINX rewrite/set heap overflow (CVE-2026-42945) RCE PoC |
| SSO Test 1 | [`sso-test-1`](./sso-test-1/) | Dockerized OpenID Connect sign-up / sign-in (lab IdP or Microsoft Entra ID) |

## Requirements

- Docker and Docker Compose for the containerized labs
- Python 3 for PoC / exploit scripts where noted in each lab

## Git

This repository root is **`/home/maruf/Desktop/Projects/PoC_Labs`**. Lab folders are not separate git repositories.

## Notes

These labs are for education and authorized testing only. Run them in isolated environments; do not point PoCs at systems you do not own or have permission to test.
