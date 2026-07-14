---
title: Domain verification
weight: 23
description: Prove domain ownership by reading a TXT challenge directly from the authoritative nameservers, deny-by-default.
---

# Domain verification

Domain-ownership verification asks the user to publish a token in DNS, then checks
that it is there. The subtlety is *where* you check. Reading the token through a
recursive resolver is unreliable: its cache can be stale (a just-published record is
invisible until an old negative TTL expires) or, on a shared resolver, poisoned.

`DomainVerifier` reads the challenge TXT record **directly from the domain's
authoritative nameservers**, so a match means the record is genuinely published at
the source of truth, right now.

## Usage

```php
use Cbox\Dns\Dns;

$dns = new Dns;

// Tell the user where to publish the token:
$dns->challengeHost('example.com');   // "_cbox-challenge.example.com"

// Later, verify it:
$dns->verifyDomain('example.com', 'my-verification-token');   // bool
```

The challenge host is `_cbox-challenge.` prefixed to the normalized domain. Publish
the token as a TXT record there.

## Deny-by-default

`verifyDomain()` returns `false` — never throws — on **any** of:

- an empty domain or empty token,
- a resolution failure (the authoritative read did not succeed),
- no challenge record present,
- a record whose value does not match the token exactly (trimmed).

It returns `true` only when the authoritative nameservers serve a TXT record whose
trimmed value equals the trimmed token. There is no partial or fuzzy match.

## How it reads authoritatively

`DomainVerifier` composes an `AuthoritativeResolver`. Verifying `example.com`:

1. resolves the `NS` set for `example.com`,
2. resolves each nameserver hostname to an IP,
3. queries `_cbox-challenge.example.com` `TXT` directly against an authoritative IP
   with recursion disabled.

See [Testing](../getting-started/testing.md) for how to stub these three layers with
`FakeResolver`, and the [verify-a-domain recipe](../cookbook/verify-a-domain.md) for
an end-to-end walkthrough.
