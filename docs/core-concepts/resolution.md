---
title: Chain resolution
weight: 27
description: Follow CNAME chains and expand SPF include/redirect trees to a complete endpoint list — both loop-safe and bounded.
---

# Chain resolution

Some answers are not one record but a *chain*: a CNAME that points at another name,
or an SPF policy that `include:`s another policy. Following those chains is an
explicit opt-in — and always loop-safe.

## Following a CNAME chain

`follow()` resolves a name for a type, follows every CNAME, and returns the hops it
traversed:

```php
use Cbox\Dns\Enums\RecordType;

$chain = $dns->follow('www.example.com', RecordType::A);

$chain->aliases();        // ['www.example.com', 'web.example.com', ...]
$chain->canonicalName();  // 'web.example.com'
$chain->values();         // ['93.184.216.34', ...]
$chain->completed;        // false + ->stoppedReason on a loop / dead end
```

It works whether or not the server flattened the chain: a recursive resolver
returns the CNAMEs and the final answer together (the hops are read out of that one
response), and an authoritative server that returns only a CNAME is chased to the
target. A name is never queried twice, so a `a → b → a` loop stops with a reason
rather than spinning.

## Expanding an SPF policy

`spf()` expands a domain's SPF record into the complete set of authorized sending
endpoints — recursively following `include:` and `redirect=`, and expanding `a` and
`mx` mechanisms into their addresses:

```php
$spf = $dns->spf('example.com');

$spf->isValid();       // an SPF record was found and no hard error occurred
$spf->allIp4();        // every authorized IPv4 prefix, flattened and de-duplicated
$spf->allIp6();
$spf->domains();       // every domain in the include/redirect tree (traceability)
$spf->lookups;         // DNS-querying mechanisms used
$spf->exceededLookupLimit;
```

The tree is walkable for traceability — `$spf->includes` is the list of nested
`SpfEvaluation`s, and `$spf->redirect` the redirect target.

### Bounded by RFC 7208

SPF expansion is where a hostile or careless policy could otherwise explode, so the
RFC 7208 §4.6.4 limits are enforced across the **whole** tree, not per include:

- **At most 10 DNS-querying mechanisms** (`include`, `a`, `mx`, `ptr`, `exists`,
  `redirect`). The 11th is refused and `exceededLookupLimit` is set — a `permerror`
  in SPF terms.
- **A domain is never evaluated twice**, so an `include:` loop terminates.
- The `mx` mechanism resolves at most 10 exchanges; void lookups are capped.

So `spf()` always terminates, whatever the policies out there look like.
