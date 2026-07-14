---
title: Testing
weight: 12
description: Use FakeResolver to drive lookups, verification, propagation, DNSSEC, and diagnostics with no network.
---

# Testing

Every capability in this library resolves DNS through the `Cbox\Dns\Contracts\Resolver`
contract. `Cbox\Dns\Testing\FakeResolver` is an in-memory implementation of that
contract, so you can drive the entire package — including the DNSSEC chain walk —
without a single network call.

## Stubbing simple answers

`stub()` records the values a `host + type` (optionally per nameserver) resolves to:

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;

$fake = (new FakeResolver)
    ->stub('example.com', RecordType::A, ['93.184.216.34']);

$dns = new Dns($fake);

expect($dns->lookup('example.com', RecordType::A)->values())
    ->toBe(['93.184.216.34']);
```

Each `stub()` call returns the fake, so calls chain.

## Modelling authoritative vs. recursive

The `nameserver` argument lets you give different servers different answers — which
is exactly how you exercise domain verification and propagation offline. A stub with
no `nameserver` acts as the wildcard fallback.

```php
$fake = (new FakeResolver)
    // The zone's NS set, and those NS hostnames resolved to IPs:
    ->stub('example.com', RecordType::NS, ['ns1.example.com'])
    ->stub('ns1.example.com', RecordType::A, ['203.0.113.1'])
    // The challenge TXT, served authoritatively by ns1's IP:
    ->stub('_cbox-challenge.example.com', RecordType::TXT, ['secret-token'], nameserver: '203.0.113.1');

$dns = new Dns($fake);

expect($dns->verifyDomain('example.com', 'secret-token'))->toBeTrue();
```

`AuthoritativeResolver` reads the `NS` set, resolves each nameserver to an IP, then
queries the target record against that IP with recursion off — so stubbing those
three layers is all it takes.

## Full responses (DNSSEC and denial-of-existence)

`stubResponse()` stores a complete `DnsResponse`, including raw DNSSEC RDATA and an
authority section. This is the seam the package's own DNSSEC chain-walk tests use to
drive each zone level offline:

```php
use Cbox\Dns\ValueObjects\DnsResponse;

$fake->stubResponse('com', RecordType::DNSKEY, $dnskeyResponse, nameserver: null);
```

Constructing signed fixtures by hand is involved; for realistic DNSSEC testing, see
how the suite builds chains under `tests/Support/` (a test zone-signer plus real
captured vectors). The point for your own tests is that no network is required.

## Why this works everywhere

`AuthoritativeResolver`, `DomainVerifier`, `PropagationChecker`, `DnssecValidator`,
and the whole `Diagnostics` engine all take a `Resolver` (directly or via the
facade). Inject a `FakeResolver` and the entire library runs deterministically and
offline.
