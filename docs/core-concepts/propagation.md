---
title: Propagation
weight: 24
description: Compare the authoritative record set against public recursive resolvers — and the honest limits of what that measures.
---

# Propagation

A propagation check answers "has my DNS change taken effect yet?" by comparing the
**authoritative** record set for a host against what a panel of **public recursive
resolvers** currently return. If they all agree, the change has propagated; if the
authoritative answer is right but some recursives still serve the old set, it is
still rolling out; if the authoritative answer itself is missing, nothing can
propagate yet.

## Usage

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationStatus;

$dns = new Dns;

$report = $dns->checkPropagation('www.example.com', RecordType::A, 'example.com');

$report->status;               // PropagationStatus enum
$report->authoritativeValues;  // list<string> — the source of truth
$report->results;              // list<ResolverResult> — each public resolver's view
$report->stale();              // the results that don't yet agree
```

### The status

| `PropagationStatus` | Meaning |
| --- | --- |
| `Propagated` | every polled resolver agrees with the authoritative set |
| `Pending` | the authoritative answer is correct, but some recursives are stale |
| `Misconfigured` | the authoritative answer itself is missing or empty |

Each `ResolverResult` carries the `nameserver` queried, the `values` it returned,
whether it `agrees` with the authoritative set, and an optional provider `label`.
Comparison is order-independent (de-duplicated and sorted).

## The default panel vs. the named registry

The facade's `checkPropagation()` polls a lean panel of six well-known public
resolver IPs (Google, Cloudflare, Quad9, OpenDNS). For a wider, **labelled** check
across the full 15-provider registry, construct the checker directly:

```php
use Cbox\Dns\Propagation\PropagationChecker;

$checker = new PropagationChecker($dns->resolver(), $dns->authoritative());

$report = $checker->checkAcrossProviders('www.example.com', RecordType::A, 'example.com');
// results are labelled: "Google Public DNS", "Cloudflare", "Quad9", ...
```

See the [propagation providers](../diagnostics/propagation-providers.md) reference
for the full registry.

## Honest scope — what this does NOT measure

Polling many public resolvers **from a single host** is a **cache-diversity**
signal: it shows whether independent recursive *operators* have each refreshed their
cache for a name. It is **not** true global geographic propagation.

Every major provider in the registry (Google, Cloudflare, Quad9, OpenDNS, …) is
**anycast**, so from one host you always reach the nearest point of presence — you
sample operators, not locations. The `region` label on a provider describes the
operator, not where the lookup was answered.

The reliable propagation signal is therefore the **authoritative-vs-recursive
diff** this report computes, not geographic coverage. Geo-distributed vantage points
(regional DoH probes exiting from multiple regions) are a documented roadmap item —
not a claim this package makes.
