---
title: Algorithms
weight: 32
description: The DNSSEC signing algorithms and DS digest types this validator accepts, the crypto backends behind them, and what is deliberately excluded.
---

# Algorithms

The validator accepts only an explicit allow-list of signing algorithms and DS
digest types. An algorithm or digest not on the list is a validation **failure**
(deny-by-default), never a silent pass.

## Supported signing algorithms

From `Cbox\Dns\Dnssec\Enums\Algorithm` (IANA DNSSEC Algorithm Numbers):

| Number | Algorithm | Backend |
| --- | --- | --- |
| 5 | RSA/SHA-1 | OpenSSL |
| 7 | RSA/SHA-1-NSEC3-SHA1 | OpenSSL |
| 8 | RSA/SHA-256 | OpenSSL |
| 10 | RSA/SHA-512 | OpenSSL |
| 13 | ECDSA P-256 / SHA-256 | OpenSSL |
| 14 | ECDSA P-384 / SHA-384 | OpenSSL |
| 15 | Ed25519 | libsodium |

RSA and ECDSA verification go through `openssl_verify`; Ed25519 goes through
`sodium_crypto_sign_verify_detached`. The signature math is never hand-rolled — the
module implements only the DNSSEC protocol around those primitives (canonical form,
key/signature encoding, key-tag matching, validity windows).

**RSA/SHA-1 (5 and 7)** are accepted only because they still appear in real chains.
They are cryptographically weak; do not depend on them.

## Deliberately excluded

Treated as unsupported and therefore `bogus`:

- **DSA** (3) and **DSA-NSEC3-SHA1** (6)
- **GOST** (12 / 23)
- **Ed448** (16)
- reserved / indirect / "private" algorithm values

## Supported DS digest types

From `Cbox\Dns\Dnssec\Enums\DigestType` (IANA DS RR Digest Algorithms):

| Number | Digest |
| --- | --- |
| 2 | SHA-256 |
| 4 | SHA-384 |

**SHA-1 (1)** is deprecated and **GOST (3)** is unsupported — both are rejected, so
a DS that uses them does not form a trust link.

## Trust anchors

The chain is anchored on the IANA root KSK DS records, held in-code
(`Cbox\Dns\Dnssec\TrustAnchor`):

- **KSK-2017**, key tag 20326 (SHA-256) — the current active root key.
- **KSK-2024**, key tag 38696 (SHA-256) — published for the next root rollover.

The root DNSKEY RRset is trusted only once a key in it matches one of these DS
records and signs the set.
