# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities through **GitHub Private Vulnerability
Reporting** on this repository:

> **Security** tab → **Report a vulnerability**

This opens a private advisory visible only to the maintainers. Please do not open
a public issue for a suspected vulnerability, and please do not disclose it
publicly until a fix is available.

Include, as far as you can: the affected version, a description of the issue, and
a minimal reproduction (ideally a failing test driven by
`Cbox\Dns\Testing\FakeResolver`, so no live network or zone is needed).

This is a volunteer, best-effort project. We will acknowledge reports and work a
fix as promptly as we reasonably can, but we do **not** commit to a fixed response
or remediation SLA, we do **not** operate a `security@` mailbox or a PGP key, and
we are **not** a CVE Numbering Authority. GitHub's advisory workflow is the single
supported channel.

## Supported versions

This library follows semantic versioning. Until a `1.0.0` release, security fixes
land on the latest `0.x` line; there is no back-porting to earlier `0.x` releases.

## DNSSEC security posture

The DNSSEC module is the security-sensitive part of this package, so its posture
is stated explicitly and honestly.

### Deny-by-default validation

Validation resolves to one of three RFC 4033 states, and anything that is not
*provably* `Secure` or *provably* `Insecure` is `Bogus`. In particular, all of the
following are rejected as `bogus` — never silently accepted:

| Condition | Outcome |
| --- | --- |
| Unknown / unsupported signing algorithm | `bogus` |
| Unsupported DS digest type (e.g. SHA-1, GOST) | `bogus` |
| Tampered / invalid RRSIG signature | `bogus` |
| Expired or not-yet-valid RRSIG (outside its validity window) | `bogus` |
| Broken DS → DNSKEY link (no key matches the parent's DS) | `bogus` |
| Key-tag / signer-name mismatch | `bogus` |
| Out-of-bailiwick signer (a zone signing a name it does not enclose) | `bogus` |
| Wildcard answer without an authenticated no-closer-match proof | `bogus` |
| Missing keys / missing signatures / empty unsigned answer | `bogus` |

`Insecure` is the *only* non-`secure` success, and it requires a positive,
authenticated NSEC/NSEC3 proof that a delegation genuinely carries no DS — a
provably-unsigned zone, not merely a missing signature.

### Signature math is delegated, not hand-rolled

The cryptographic verification is done by vetted primitives, never by bespoke
big-integer or curve code:

- **RSA and ECDSA (P-256 / P-384)** — `openssl_verify` (`ext-openssl`).
- **Ed25519** — `sodium_crypto_sign_verify_detached` (`ext-sodium`).

The module's own code handles only the DNSSEC *protocol*: canonical RR ordering
and name form, DNSKEY/RRSIG wire decoding, key-tag computation, algorithm
selection against an allow-list, validity-window checks, and NSEC/NSEC3 denial
logic. Algorithms are pinned by an allow-list; an unrecognised algorithm number is
a validation *failure*, closing off algorithm-confusion.

### Trust from cryptography, not transport

The chain is anchored on the **IANA root KSK DS records** (KSK-2017 tag 20326 and
KSK-2024 tag 38696, SHA-256), held in-code as the out-of-band trust anchor. Because
every signature is checked against an anchored key, the records themselves may be
fetched over any transport — including a plain recursive query with the DO bit —
without weakening the result. The `AD` (authenticated-data) bit reported by a
recursive resolver or DoH provider is treated as *advisory only* and is never a
substitute for chain validation.

### Testing and review — honest scope

- The validator is tested against **real captured signed-zone vectors** (e.g. the
  live Cloudflare DNSKEY/DS material under `tests/Fixtures/`) and against
  self-signed chains produced by a test zone-signer, so both real-world and
  adversarial cases are exercised offline.
- The module was **adversarially security-reviewed** before release. That review
  found a **cross-zone forgery bypass** — a zone whose own chain validated could
  present a signature over a name it did not enclose — which is now closed by
  strict in-bailiwick (label-aligned ancestor) enforcement on every signer, with a
  dedicated regression test.

This is genuine engineering care, not a certification. This package has **not**
undergone a formal third-party security audit and makes **no** conformance-
certification claim. Treat it accordingly.
