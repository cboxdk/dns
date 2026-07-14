---
title: Validation
weight: 31
description: Walk the DNSSEC chain from the IANA root to a zone, or validate a single record set, and read the Secure/Insecure/Bogus result.
---

# Validation

## The chain walk

`DnssecValidator` is anchored on the IANA root trust anchors (the KSK DS records).
Given a zone, it walks root → TLD → zone. At each level it:

1. fetches the `DNSKEY` RRset (with the DO bit),
2. proves one key against the `DS` committed by the parent (the root uses the
   hard-coded anchor),
3. verifies the zone's DNSKEY self-signature with that key,
4. only then trusts the zone's keys to authenticate the next step down.

Trust comes from the cryptography, not the transport: because every signature is
checked against an anchored key, the records may be fetched over any `Resolver` — a
recursive DO query, a fake — without weakening the result.

## Validating a zone

```php
use Cbox\Dns\Dns;

$dns = new Dns;

$result = $dns->dnssec()->validate('cloudflare.com');

$result->status->value;   // "secure" | "insecure" | "bogus"
$result->isSecure();      // bool
$result->isInsecure();
$result->isBogus();
$result->target;          // "cloudflare.com"
$result->reason;          // human-readable explanation
```

`$dns->dnssec()` returns a fresh `DnssecValidator` bound to the facade's resolver.
`validate()` returns a `ValidationResult`.

## Validating a single record set

`validateRecords()` fetches a specific `host`/`type` with the DO bit, learns the
signing zone from the RRSIG's signer name, validates that zone's chain, and verifies
the RRset against the zone's keys:

```php
use Cbox\Dns\Enums\RecordType;

$dns->dnssec()->validateRecords('www.cloudflare.com', RecordType::A);
```

An **empty** answer is not a silent pass — it is validated as an authenticated
NODATA/NXDOMAIN via NSEC/NSEC3, or it is `bogus`.

## The three outcomes

| Status | Meaning |
| --- | --- |
| `Secure` | a complete authentication chain from a trust anchor was proven |
| `Insecure` | an authenticated NSEC/NSEC3 proof shows the zone is genuinely unsigned (a delegation with no DS) |
| `Bogus` | validation was expected to succeed but failed — a missing key, a broken DS link, a bad or expired signature, or an unknown algorithm |

`Bogus` is the deny-by-default outcome: **anything that is not provably `Secure` or
provably `Insecure` is `Bogus`.** See the [threat model](threat-model.md) for the
full matrix of what maps to `bogus`, and [algorithms](algorithms.md) for which
signing algorithms are accepted.

## What the AD bit is (and isn't)

`DnsResponse::$authenticated` carries the `AD` (authenticated-data) bit when a
transport reports it — DoH JSON exposes it directly. It only tells you that *some
other* validator upstream claims to have validated. It is advisory. Never treat a
bare `authenticated === true` as a substitute for running `validate()` /
`validateRecords()` yourself.
