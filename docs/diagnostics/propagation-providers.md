---
title: Propagation providers
weight: 42
description: The named public-resolver registry used by propagation checks, and the honest meaning of its region labels.
---

# Propagation providers

`Cbox\Dns\Propagation\PublicResolvers` is a registry of well-known public recursive
resolvers as named `PublicResolver` value objects, so a propagation report can read
"Google Public DNS / Cloudflare / Quad9" instead of bare IPs.

Each `PublicResolver` has a machine `name`, a human `label`, the `ip` to query, and
an optional `region`.

## The registry

`PublicResolvers::all()` — the full 15-entry set used by `checkAcrossProviders()`:

| name | label | ip | region |
| --- | --- | --- | --- |
| `google-primary` | Google Public DNS | 8.8.8.8 | Global (anycast) |
| `google-secondary` | Google Public DNS | 8.8.4.4 | Global (anycast) |
| `cloudflare-primary` | Cloudflare | 1.1.1.1 | Global (anycast) |
| `cloudflare-secondary` | Cloudflare | 1.0.0.1 | Global (anycast) |
| `quad9` | Quad9 | 9.9.9.9 | Global (anycast) |
| `opendns-primary` | OpenDNS | 208.67.222.222 | Global (anycast) |
| `opendns-secondary` | OpenDNS | 208.67.220.220 | Global (anycast) |
| `level3-primary` | Level3 | 4.2.2.1 | Global (anycast) |
| `level3-secondary` | Level3 | 4.2.2.2 | Global (anycast) |
| `verisign` | Verisign Public DNS | 64.6.64.6 | Global (anycast) |
| `adguard` | AdGuard DNS | 94.140.14.14 | Global (anycast) |
| `dns-watch` | DNS.Watch | 84.200.69.80 | Germany |
| `neustar` | Neustar UltraDNS | 156.154.70.1 | Global (anycast) |
| `yandex` | Yandex DNS | 77.88.8.8 | Russia |
| `comodo` | Comodo Secure DNS | 8.26.56.26 | Global (anycast) |

`PublicResolvers::default()` — the lean six-entry panel (one or two per major
operator) used by `PropagationChecker::check()` when no wider set is requested,
kept small so a check stays fast: the two Google IPs, the two Cloudflare IPs, Quad9,
and OpenDNS primary.

## What `region` means (and doesn't)

`region` is the operator's stated location, or "Global (anycast)". It is **not** a
geographic vantage point. Querying `8.8.8.8` from your host still exits through your
own uplink and lands on the nearest anycast PoP — so `region` labels the operator,
not where the lookup was answered.

This is why a multi-provider check is a **cache-diversity** signal across independent
operators, not global geographic propagation. Geo-distributed vantage points are a
documented roadmap non-goal here. See [Propagation](../core-concepts/propagation.md)
for the full honest scope.
