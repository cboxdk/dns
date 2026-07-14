---
title: Quickstart
weight: 2
description: Install the package and run every capability — lookup, verify, propagation, DNSSEC, diagnostics — in one read.
---

# Quickstart

## Install

```bash
composer require cboxdk/dns
```

Requires PHP 8.4+ and `ext-sockets`. DNSSEC validation additionally uses
`ext-openssl` and `ext-sodium` (both ship with a stock PHP build). See
[Requirements](requirements.md).

## The facade

`Cbox\Dns\Dns` is the front door. Construct it with no arguments to use the raw
socket resolver, or pass any `Resolver` (a DoH resolver, a fake) to redirect every
call.

```php
use Cbox\Dns\Dns;

$dns = new Dns;
```

## Look a record up

```php
use Cbox\Dns\Enums\RecordType;

$response = $dns->lookup('example.com', RecordType::A);

$response->values();                 // ['93.184.216.34', ...]
$response->contains('93.184.216.34');
$response->isEmpty();
$response->rcode;                    // Rcode::NoError | NxDomain | ServFail | …
$response->isNxDomain();             // the name provably does not exist

foreach ($response->records as $record) {
    // $record->type, $record->name, $record->value, $record->ttl, $record->priority
}
```

`RecordType` covers `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `CAA`,
`SRV`, `NAPTR`, `TLSA`, `SVCB`, `HTTPS`, and the DNSSEC types (`DS`, `RRSIG`,
`DNSKEY`, `NSEC`, `NSEC3`).

## Typed record data — no string parsing

Call `data()` on a record (or a whole response) for a typed value object, so you
read fields instead of splitting `value` strings or touching raw bytes:

```php
foreach ($dns->lookup('example.com', RecordType::MX)->data() as $mx) {
    $mx->preference;   // 10
    $mx->exchange;     // 'mail.example.com'
}

$soa = $dns->lookup('example.com', RecordType::SOA)->data()[0];
$soa->serial;          // 2024010101
$soa->refresh;

// SVCB/HTTPS SvcParams are fully parsed — ALPN, port, address hints, ECH:
foreach ($dns->lookup('cloudflare.com', RecordType::HTTPS)->data() as $https) {
    $https->alpn;      // ['h3', 'h2']
    $https->ipv4hint;  // ['104.16.132.229', ...]
    $https->port;
}
```

Each type maps to an object — `A`/`AAAA` → `Address`, `CNAME`/`NS`/`PTR` → `Name`,
`TXT` → `Txt`, `MX` → `Mx`, `SRV` → `Srv`, `SOA` → `Soa`, `CAA` → `Caa`, `NAPTR` →
`Naptr`, `TLSA` → `Tlsa`, `SVCB`/`HTTPS` → `Svcb`. The DNSSEC types are parsed and
validated by the [DNSSEC module](dnssec/_index.md) (`$dns->dnssec()`), so
`data()` returns `null` for them.

## Verify domain ownership

Ownership is proven by reading a TXT challenge **directly from the domain's
authoritative nameservers** — never a recursive cache.

```php
// Where the user must publish the token:
$dns->challengeHost('example.com');   // "_cbox-challenge.example.com"

// Verify (deny-by-default: any failure or mismatch returns false):
$dns->verifyDomain('example.com', 'my-verification-token');   // bool
```

## Check propagation

```php
use Cbox\Dns\Propagation\PropagationStatus;

$report = $dns->checkPropagation('www.example.com', RecordType::A, 'example.com');

$report->status;               // Propagated | Pending | Misconfigured
$report->authoritativeValues;  // the source-of-truth set
$report->stale();              // ResolverResult[] not yet caught up

foreach ($report->results as $result) {
    // $result->nameserver, $result->values, $result->agrees, $result->label
}
```

## Validate DNSSEC

```php
$result = $dns->dnssec()->validate('cloudflare.com');

$result->status->value;   // "secure" | "insecure" | "bogus"
$result->isSecure();
$result->reason;          // e.g. "authentication chain to cloudflare.com is complete"
```

Or validate a single record set (a signed answer, or an authenticated proof that a
name/type is absent):

```php
$dns->dnssec()->validateRecords('www.cloudflare.com', RecordType::A);
```

## Run a full health check

```php
$report = $dns->diagnose('example.com');

$report->passed();      // true only if no errors AND no warnings
$report->hasErrors();
$report->bySeverity();  // ['error' => [...], 'warning' => [...], 'info' => [...]]
$report->byCategory();  // ['Delegation' => [...], 'Email' => [...], ...]

foreach ($report->findings as $finding) {
    echo "[{$finding->severity->value}] {$finding->category}: {$finding->message}\n";
}
```

## Next

- Drive everything offline in tests → [Testing](getting-started/testing.md).
- Understand the resolvers → [Resolvers](core-concepts/resolvers.md).
- The full check catalog → [Diagnostics checks](diagnostics/checks.md).
