# Security Policy

## Supported Versions

Chhaya is still evolving rapidly. We provide security fixes for the actively
developed `main` branch and the most recent published release line. Older
releases should be upgraded as soon as possible to stay covered by patches and
protocol hardening updates.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take the security of the Chhaya network seriously. Please report suspected
vulnerabilities or weaknesses privately so we can investigate and roll out a
fix before public disclosure.

1. Email `necoarc007@proton.me` with a concise description of the issue,
   including steps to reproduce, the impacted components (for example: `p2p`,
   `vkd`, or `logstore`), and any proof-of-concept material. Do not open a
   public GitHub issue for security reports.
2. Encrypt sensitive details with the Chhaya security PGP key below and attach
   the encrypted payload to your email.
3. Expect an initial acknowledgement during the upcoming weekend after we
   receive your report. We will provide follow-up status updates each weekend
   until the issue is resolved.
4. After verification, we will coordinate a fix, prepare any necessary security
   advisories, and agree on a disclosure timeline that balances remediation and
   user safety. Credit will be given unless you request anonymity.

### Security Contact PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaM/niRYJKwYBBAHaRw8BAQdA/PMzX/brAUP7wvpEYW8YW30yb04o3MjeLGif
1vneOhO0JE5vbW5vbXNoYXJrNDEgPG5lY29hcmMwMDdAcHJvdG9uLm1lPoiZBBMW
CgBBFiEESwoGPlHiS3nSX6ymnUbvfHy5xZUFAmjP54kCGwMFCQHhM4AFCwkIBwIC
IgIGFQoJCAsCBBYCAwECHgcCF4AACgkQnUbvfHy5xZUB8wEAkKIfFqPmLPygby4A
Iq0bVV/T88/yvXol7kThy/vzozABAML99WKC8ZhF/1IjlEo5Z0g4OoTH2I7Nj3Lv
qAJRpMcGuDgEaM/niRIKKwYBBAGXVQEFAQEHQNQ7Ws2Po08xrlcZYxTcDo7Iqw6w
UAWJEb9GEK+B3tNYAwEIB4h+BBgWCgAmFiEESwoGPlHiS3nSX6ymnUbvfHy5xZUF
AmjP54kCGwwFCQHhM4AACgkQnUbvfHy5xZV4vAD/XBQvjuyIxdRbmbthDlSpsxkJ
e+kWhsZppVylmMbZQdMA/12pZsni1LmHf2I6VNx0ZfpVQr/RzLSt0/NShYDzZrQE
=b75s
-----END PGP PUBLIC KEY BLOCK-----
```

- **Fingerprint:** `4B0A 063E 51E2 4B79 D25F  ACA6 9D46 EF7C 7CB9 C595`
- **Created:** 2025-09-21
- **Expires:** 2026-09-21 (rotates sooner if the key is compromised)

If you believe the vulnerability affects third-party ecosystems (for example,
upstream crates we depend on), please mention this so we can coordinate a joint
response.

Thank you for helping us keep the Chhaya protocol secure for everyone.
