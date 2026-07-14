---
title: DNSSEC
weight: 30
description: Root-anchored DNSSEC chain validation — how it works, which algorithms are supported, and the deny-by-default threat model.
---

# DNSSEC

The DNSSEC module walks and validates the DNS authentication chain itself, anchored
on the IANA root trust anchors. It does not trust a resolver's `AD` bit — it checks
every signature. The protocol work is this package's; the signature math is
delegated to OpenSSL and libsodium.

- **[Validation](validation.md)** — the chain walk, `validate()` vs.
  `validateRecords()`, and the three outcomes.
- **[Algorithms](algorithms.md)** — the supported signing algorithms and DS digest
  types, and what is deliberately excluded.
- **[Threat model](threat-model.md)** — the deny-by-default matrix and the honest
  security posture.
