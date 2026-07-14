---
title: Security
weight: 60
description: The library's threat model, the deny-by-default posture, reporting channel, and honest scope.
---

# Security

## Reporting

Report vulnerabilities through **GitHub Private Vulnerability Reporting** on the
repository (the **Security** tab → **Report a vulnerability**). Please do not open a
public issue for a suspected vulnerability. This is a best-effort project — there is
no `security@` mailbox, PGP key, response SLA, or CVE pipeline; GitHub's advisory
workflow is the single supported channel. The full policy is in the repository's
[`SECURITY.md`](https://github.com/cboxdk/dns/blob/main/SECURITY.md).

## What this library defends

The security-sensitive design decisions, and where each is documented:

### Authoritative reads over cached reads

Domain [verification](../core-concepts/domain-verification.md) and
[propagation](../core-concepts/propagation.md) read from a zone's **authoritative
nameservers**, not a recursive cache. A recursive cache can be stale or, on a shared
resolver, poisoned — so trusting it for an ownership decision is unsafe. Verification
is **deny-by-default**: any failure or non-exact match returns `false`.

### DNSSEC validation, deny-by-default

The [DNSSEC module](../dnssec/_index.md) validates the chain itself rather than
trusting a resolver's `AD` bit. Anything not *provably* `Secure` or *provably*
`Insecure` is `Bogus`: unknown algorithm, tampered or expired signature, broken DS
link, out-of-bailiwick signer, unproven wildcard — all rejected. See the full
[threat model](../dnssec/threat-model.md) and the deny-by-default matrix.

Key posture points:

- Signature math is delegated to **OpenSSL** (RSA/ECDSA) and **libsodium**
  (Ed25519) — never hand-rolled.
- Algorithms are **pinned to an allow-list**; an unrecognised algorithm is a
  failure, closing off algorithm-confusion.
- The chain is anchored on the **IANA root KSK** DS records held in-code; trust
  comes from the cryptography, not the transport.
- Signers are **in-bailiwick enforced** — a validly-signed zone cannot forge another
  zone's records. This closes a cross-zone forgery bypass found during pre-release
  adversarial review.

### Testing and review — honest scope

The DNSSEC module is tested against **real captured signed-zone vectors** and
self-signed test chains, and was **adversarially security-reviewed** before release.
It has **not** had a formal third-party audit, and the package makes **no**
conformance-certification claim. Treat it as carefully-engineered, not certified.

## Out of scope

This is a DNS-only library. It does not perform live SMTP probing, RBL/blacklist
lookups, or geo-distributed measurement — see the [diagnostics scope](../diagnostics/_index.md).
It reads DNS; it does not manage zones, write records, or act as a resolver daemon.
