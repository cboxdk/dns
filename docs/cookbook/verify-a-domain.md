---
title: Verify a domain
weight: 51
description: Issue a verification token, show the user the challenge host, and confirm ownership against the authoritative nameservers.
---

# Verify a domain

The goal: prove a user controls a domain by having them publish a token in DNS, then
confirming it **authoritatively** (so a stale or poisoned recursive cache can't give
a false positive or negative).

## 1. Issue a token and show where it goes

```php
use Cbox\Dns\Dns;

$dns = new Dns;

$token = bin2hex(random_bytes(16));   // store this against the pending verification

$host = $dns->challengeHost('example.com');   // "_cbox-challenge.example.com"

// Tell the user: add a TXT record at {$host} with value {$token}
```

## 2. Verify it

```php
if ($dns->verifyDomain('example.com', $token)) {
    // Ownership proven — the token is published at example.com's authoritative NS.
} else {
    // Not yet (or mismatch). Deny-by-default: verifyDomain never throws.
}
```

`verifyDomain()` reads the challenge TXT directly from `example.com`'s authoritative
nameservers with recursion disabled, and returns `true` only on an exact (trimmed)
match. Any resolution failure, missing record, or mismatch is `false`.

## 3. Test it offline

Model the three layers the authoritative read walks — the NS set, the NS IP, and the
TXT record served by that IP — with a `FakeResolver`:

```php
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;

$fake = (new FakeResolver)
    ->stub('example.com', RecordType::NS, ['ns1.example.com'])
    ->stub('ns1.example.com', RecordType::A, ['203.0.113.1'])
    ->stub('_cbox-challenge.example.com', RecordType::TXT, [$token], nameserver: '203.0.113.1');

expect((new Dns($fake))->verifyDomain('example.com', $token))->toBeTrue();
```

See [Domain verification](../core-concepts/domain-verification.md) for why the
authoritative read matters.
