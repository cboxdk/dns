---
title: Overview
weight: 1
description: A zero-dependency PHP DNS toolkit — authoritative resolution, domain verification, propagation, DNSSEC, and diagnostics behind one contract.
---

# cboxdk/dns

`cboxdk/dns` is a zero-runtime-dependency DNS toolkit for PHP 8.4+. It speaks the
DNS wire protocol over raw sockets, which lets it read a zone's answer **from the
zone's own authoritative nameservers** rather than from a recursive resolver's
cache. That single capability is the foundation for everything else: reliable
domain-ownership verification, honest propagation checking, DNSSEC chain
validation, and a full diagnostics engine.

## Mental model

Everything is built on one contract — `Cbox\Dns\Contracts\Resolver`:

```php
public function query(
    string $host,
    RecordType $type,
    ?string $nameserver = null,   // target a specific server...
    bool $recursion = true,       // ...with recursion off, to read a zone directly
    bool $dnssec = false,         // set the EDNS0 DO bit to fetch RRSIG/DNSKEY/DS
): DnsResponse;
```

Three implementations ship: `SocketResolver` (raw UDP/TCP, the default),
`HttpsResolver` (DNS-over-HTTPS), and `FakeResolver` (in-memory, for tests). Every
higher-level capability composes a `Resolver`, so the whole library is drivable
offline by swapping in the fake.

The facade `Cbox\Dns\Dns` wires the common tasks together so each is a single call:

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;

$dns = new Dns;                                             // default socket resolver

$dns->lookup('example.com', RecordType::MX);               // DnsResponse
$dns->verifyDomain('example.com', $token);                 // bool (authoritative)
$dns->checkPropagation('www.example.com', RecordType::A, 'example.com');
$dns->dnssec()->validate('cloudflare.com');                // ValidationResult
$dns->diagnose('example.com');                             // Report
```

Everything the facade composes is public, so you can reach past it —
`$dns->resolver()`, `$dns->authoritative()` — whenever you need finer control.

## Sections

- **[Quickstart](quickstart.md)** — zero to working in one read.
- **[Requirements](requirements.md)** — PHP and extension versions.
- **[Getting started](getting-started/_index.md)** — installation and testing with
  the `FakeResolver`.
- **[Core concepts](core-concepts/_index.md)** — the resolvers, authoritative
  reads, domain verification, propagation, and the overall architecture.
- **[DNSSEC](dnssec/_index.md)** — chain validation, supported algorithms, and the
  deny-by-default threat model.
- **[Diagnostics](diagnostics/_index.md)** — the check catalog and the propagation
  provider registry.
- **[Cookbook](cookbook/_index.md)** — task-oriented recipes.
- **[Security](security/_index.md)** — threat model and honest scope.

## Scope

This is a DNS-only library. Live SMTP diagnostics, RBL/blacklist lookups, and
geo-distributed propagation vantage points are deliberately **out of v1** — see
[Diagnostics](diagnostics/_index.md) and [Propagation](core-concepts/propagation.md)
for the honest boundaries.
