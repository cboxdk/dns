---
title: Threat model
weight: 33
description: The deny-by-default rejection matrix, in-bailiwick enforcement, and the honest security posture of the DNSSEC module.
---

# DNSSEC threat model

## Deny-by-default

Validation resolves to one of three RFC 4033 states. Anything that is not *provably*
`Secure` or *provably* `Insecure` is `Bogus`. In particular, every one of these is
rejected as `bogus` — never silently accepted:

| Condition | Outcome |
| --- | --- |
| Unknown / unsupported signing algorithm | `bogus` |
| Unsupported DS digest type (SHA-1, GOST) | `bogus` |
| Tampered / invalid RRSIG signature | `bogus` |
| Expired or not-yet-valid RRSIG (outside its validity window) | `bogus` |
| Broken DS → DNSKEY link (no zone key matches the parent's DS) | `bogus` |
| Key-tag mismatch between RRSIG and DNSKEY | `bogus` |
| Out-of-bailiwick signer (a zone signing a name it does not enclose) | `bogus` |
| Answer record not owned by the queried name | `bogus` |
| Wildcard answer without an authenticated no-closer-match proof | `bogus` |
| Missing keys / missing signatures | `bogus` |
| Empty answer with no signatures to prove absence | `bogus` |

`Insecure` is the **only** non-`secure` success. It requires a positive,
authenticated NSEC/NSEC3 proof that a delegation genuinely carries no DS — a
provably-unsigned zone, not merely a missing signature.

## In-bailiwick enforcement (cross-zone forgery)

A signer zone is only accepted if it is a **label-aligned ancestor** of the name it
signs (RFC 4035 §5.3.1). This closes a real class of attack: without it, any zone
whose *own* chain validates could present a signature over a name it does not
enclose and have it accepted. Concretely, `evil.com` is **not** in-bailiwick for
`notevil.com` (suffix match must be on whole labels), and the root is in-bailiwick
for everything.

This exact bypass — a cross-zone forgery where a validly-signed zone forged another
zone's records — was found during pre-release adversarial review and is now closed,
with a dedicated regression test. See [Security](../security/_index.md).

## Trust from cryptography, not transport

Because every signature is verified against a key anchored to the IANA root, the
records themselves can be fetched over any transport (a plain recursive DO query, a
fake) without weakening the result. The recursive resolver's `AD` bit is advisory
only and never substitutes for chain validation.

## Honest posture

- The signature math is delegated to **OpenSSL** (RSA/ECDSA) and **libsodium**
  (Ed25519) — never bespoke crypto.
- The module is tested against **real captured signed-zone vectors** and against
  self-signed chains from a test zone-signer, so both genuine and adversarial cases
  run offline.
- It was **adversarially security-reviewed** before release (the cross-zone forgery
  above was found and fixed).

This is engineering care, not certification. The package has **not** had a formal
third-party security audit and claims **no** conformance certification. Treat it
accordingly, and report anything you find via
[GitHub Private Vulnerability Reporting](../security/_index.md).
