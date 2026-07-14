---
title: Architecture
weight: 21
description: One Resolver contract, a thin facade, and capabilities composed on top — every layer fakeable.
---

# Architecture

## One contract

Everything starts with `Cbox\Dns\Contracts\Resolver`:

```php
interface Resolver
{
    public function query(
        string $host,
        RecordType $type,
        ?string $nameserver = null,
        bool $recursion = true,
        bool $dnssec = false,
    ): DnsResponse;
}
```

- `nameserver` targets a specific server. Pass an authoritative nameserver's IP with
  `recursion: false` to read a zone directly, bypassing any recursive cache.
- `dnssec` sets the EDNS0 DO bit to request RRSIG/DNSKEY/DS/NSEC/NSEC3. Transports
  that cannot carry those ignore it. DNSSEC *trust* comes from validating those
  signatures, never from the transport, so fetching them over a recursive query is
  a safe path.

Three implementations ship: [`SocketResolver`, `HttpsResolver`, and `FakeResolver`](resolvers.md).

## Value objects

A `query()` returns a `DnsResponse`:

| Member | Meaning |
| --- | --- |
| `records` | the answer records of the queried type (`list<DnsRecord>`) |
| `values()` | those records' values as `list<string>` |
| `contains($v)` / `isEmpty()` | convenience predicates |
| `nameserver` | which server answered |
| `authoritative` | the AA bit — a direct authoritative answer |
| `authenticated` | the DNSSEC `AD` bit when the transport reports it (advisory only) |
| `answer` / `answerOfType()` | full answer section (queried type plus its RRSIGs) |
| `authority` / `authorityOfType()` | authority section (NSEC/NSEC3 denial proofs live here) |

Each `DnsRecord` carries `type`, `name`, `value`, `ttl`, an optional `priority`
(MX/SRV), and an optional `raw` — the exact on-the-wire RDATA bytes, kept because
DNSSEC canonical-form signature reconstruction needs byte fidelity a normalized
value would lose.

## The facade

`Cbox\Dns\Dns` is a thin facade that wires the common tasks into single calls. It
composes an `AuthoritativeResolver` and a `DomainVerifier` over whatever `Resolver`
you give it (default `SocketResolver`), and constructs the propagation checker,
DNSSEC validator, and diagnostics engine on demand.

```php
$dns = new Dns($resolver);

$dns->lookup(...);            // straight through the resolver
$dns->verifyDomain(...);      // via DomainVerifier -> AuthoritativeResolver
$dns->checkPropagation(...);  // via PropagationChecker
$dns->dnssec();               // a DnssecValidator on this resolver
$dns->diagnose(...);          // the Diagnostics engine

$dns->resolver();             // the underlying Resolver
$dns->authoritative();        // the AuthoritativeResolver seam
```

Everything the facade composes is public, so a host can reach past it whenever it
needs finer control (a custom check list, a directly-constructed
`PropagationChecker`, etc.).

## Layering

```
                 Dns (facade)
        ┌───────────┼───────────────┬───────────────┐
   DomainVerifier   │        PropagationChecker   Diagnostics
        │           │               │               │
   AuthoritativeResolver ───────────┘         DnssecValidator
        │                                           │
        └──────────────── Resolver ─────────────────┘
                    (Socket | Https | Fake)
```

Because every layer depends only on the `Resolver` contract, injecting a
[`FakeResolver`](../getting-started/testing.md) drives the entire stack offline.
