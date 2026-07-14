---
title: Delegation tracing
weight: 26
description: Walk a name's delegation from the root down, and the reverse chain for an IP — loop-safe, like dig +trace.
---

# Delegation tracing

`DelegationTracer` answers "how is this name delegated?" the way `dig +trace` does:
starting at the IANA root servers, it asks an authoritative server at each level
(recursion off), follows the referral to the child zone, and records the hop —
until it reaches the zone that answers authoritatively.

```php
$trace = $dns->trace('www.example.com');

$trace->path();                      // ['.', 'com', 'example.com']
$trace->completed;                   // true
$trace->authoritativeNameservers();  // ['ns1.example.com', ...]

foreach ($trace->hops as $hop) {
    // $hop->zone, $hop->serverName, $hop->serverIp
    if ($hop->isReferral()) {
        // $hop->childZone, $hop->referralNameservers, $hop->glue (name => IP)
    }
}
```

## Reverse (IP / CIDR) tracing

`traceReverse()` builds the `in-addr.arpa` / `ip6.arpa` name for an IP and traces
its delegation — which is where reverse-zone and CIDR delegation lives (including
RFC 2317 classless delegation):

```php
$dns->traceReverse('8.8.8.8')->path();
// ['.', 'in-addr.arpa', '8.in-addr.arpa', '8.8.8.in-addr.arpa']
```

## Loop-safe by construction

A trace can never spin on a broken or hostile delegation:

- **Every step must descend.** A referral is followed only if the child zone is a
  strictly-longer, in-bailiwick descendant of the current zone — a referral that
  points sideways, back up, or to the same zone stops the trace.
- **Visited zones are refused**, so a delegation cycle terminates.
- **The walk is bounded** by `DelegationTracer::MAX_HOPS`, and glue-less nameserver
  resolution is capped.
- **Dead ends end with a reason, not an exception.** If no server for a zone
  answers, `completed` is `false` and `stoppedReason` explains why; a per-server
  failure is caught and the next server tried.

Glue (the referral nameservers' addresses) is read from the response's additional
section when present, and only public addresses are used — the same SSRF safeguard
as the [authoritative resolver](resolvers.md). All queries flow through the injected
resolver, so a `FakeResolver` drives a trace offline.
