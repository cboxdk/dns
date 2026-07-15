---
title: Performance & when to use
weight: 28
description: Every lookup is a fresh, uncached round-trip — so this toolkit is for freshness and transparency (verification, diagnostics, forensics, DNSSEC), not a high-throughput hot-path resolver.
---

# Performance & when to use

**Every lookup is a fresh network round-trip. There is no cache.** That is
deliberate: the library talks to authoritative nameservers (or a chosen resolver)
directly and uncached, so what it returns is the ground truth *at this instant*.
The trade-off is speed — a lookup here does real DNS I/O every time and is
materially slower than your operating system's resolver, which answers most
queries from a warm cache in well under a millisecond.

So the deciding question is **freshness/transparency vs. throughput.**

## Use this toolkit when freshness or transparency matters

- **Domain-ownership verification** — you must see a just-published TXT record
  immediately, not wait out a recursive resolver's negative (NXDOMAIN) cache. See
  [Domain verification](domain-verification.md).
- **DNS debugging & diagnostics** — intoDNS/MxToolbox-style health checks,
  delegation traces, propagation comparisons. See [Diagnostics](../diagnostics/_index.md).
- **Forensic / point-in-time inspection** — "what does this actually resolve to at
  the authority, right now," independent of any cache.
- **DNSSEC validation** — you want to walk and check the chain yourself, not trust
  a resolver's cached `AD` bit. See [DNSSEC](../dnssec/_index.md).

## Do NOT use it as a hot-path resolver

Do not drop it in as a general-purpose resolver where throughput dominates:
per-request name resolution, high-volume batch resolving, or an **SSRF guard that
resolves-and-pins on every outbound call**. There, a cached system resolver
(`dns_get_record` / `getaddrinfo`) is faster and more robust — it uses the OS's
configured, cached DNS path, which also survives egress-restricted environments
where raw UDP/53 to a public resolver may be blocked. And such callers do not need
authoritative freshness: they resolve, pin the result, and connect.

Right tool for verification, diagnostics, and DNSSEC. Wrong tool for a
caching hot-path resolver.
