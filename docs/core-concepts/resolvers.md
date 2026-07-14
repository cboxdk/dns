---
title: Resolvers
weight: 22
description: The three transports — raw socket, DNS-over-HTTPS, and the cache-bypassing authoritative resolver.
---

# Resolvers

## SocketResolver — the raw transport

`SocketResolver` speaks DNS over UDP sockets directly, retrying over TCP when a
response is truncated (RFC 1035 §4.2.2). No `dig` binary, no runtime dependency
beyond `ext-sockets`. It is the default the facade uses.

```php
use Cbox\Dns\Resolvers\SocketResolver;
use Cbox\Dns\Enums\RecordType;

$resolver = new SocketResolver(
    defaultNameserver: '1.1.1.1',   // default
    timeout: 3.0,                   // seconds
    attempts: 2,                    // UDP retries before giving up
    zeroX20: false,                 // opt-in mixed-case anti-spoofing (see below)
);

$resolver->query('example.com', RecordType::A);

// Target a specific server, recursion off — read a zone at its own NS:
$resolver->query('example.com', RecordType::SOA, nameserver: '203.0.113.1', recursion: false);
```

**Trustworthy answers.** A response is accepted only when its transaction ID and
echoed question (name + type) match the query — a spoofed off-path datagram is
rejected as malformed. `zeroX20: true` additionally randomises the query name's
letter case and requires an exact-case echo, for extra entropy; it is off by default
because a minority of authoritative servers normalise case and would then be
unreachable.

**RCODE, IPv6, and IDN.** The response code is surfaced on `DnsResponse::$rcode`
(and `isNxDomain()` / `isServFail()` / `succeeded()`), so "the name doesn't exist"
is distinct from "no record of this type" and from "the server failed". IPv6
nameserver literals are handled, and internationalized names are punycoded (needs
`ext-intl` for non-ASCII input).

**Concurrent batches.** `SocketResolver` implements `ConcurrentResolver`, so a whole
panel of nameservers is polled under a single timeout budget rather than one at a
time — this is what makes the propagation check fast:

```php
use Cbox\Dns\ValueObjects\QueryRequest;

$resolver->queryConcurrently([
    new QueryRequest('example.com', RecordType::A, '8.8.8.8'),
    new QueryRequest('example.com', RecordType::A, '1.1.1.1'),
]);   // list<DnsResponse>, index-aligned
```

## HttpsResolver — DNS-over-HTTPS

`HttpsResolver` speaks the JSON DoH API shared by Google and Cloudflare, behind the
same `Resolver` contract. It maps the JSON `Answer[]` array to `DnsRecord`s of the
requested type, and surfaces the provider's DNSSEC-validated `AD` flag on
`DnsResponse::$authenticated`.

```php
use Cbox\Dns\Resolvers\HttpsResolver;

$google     = new HttpsResolver;                             // HttpsResolver::GOOGLE
$cloudflare = new HttpsResolver(HttpsResolver::CLOUDFLARE);

$dns = new Dns($cloudflare);
```

DoH answers come from the provider's **recursive** resolver, so they are never
authoritative — use `AuthoritativeResolver` when you need the zone's own view.
Accordingly, `HttpsResolver` **refuses** a query that targets a specific
`nameserver` or asks for `recursion: false` (it throws `ResolutionFailed`) rather
than silently returning a recursive answer for an authoritative question. It maps
the DoH `Status` field to `DnsResponse::$rcode`.

**Zero runtime dependency:** HTTP goes through an injectable fetcher —
`callable(string $url): ?string`. The default uses `file_get_contents` with a
stream context; tests inject a fetcher that returns canned JSON, so the suite never
touches the network:

```php
$resolver = new HttpsResolver(
    endpoint: HttpsResolver::GOOGLE,
    fetcher: fn (string $url): string => $cannedJson,
);
```

## AuthoritativeResolver — the cache-bypassing reader

`AuthoritativeResolver` reads a record straight from a zone's authoritative
nameservers, bypassing every recursive cache. This is the reliable path for
[domain verification](domain-verification.md) and [propagation](propagation.md).

It composes a `Resolver` and works in two steps:

```php
use Cbox\Dns\Resolvers\AuthoritativeResolver;
use Cbox\Dns\Resolvers\SocketResolver;

$authoritative = new AuthoritativeResolver(new SocketResolver);

// 1. Discover the zone's authoritative server IPs:
$authoritative->authoritativeFor('example.com');   // ['203.0.113.1', ...]

// 2. Query a record directly against them, recursion off (first server that answers):
$authoritative->query('www.example.com', RecordType::A, 'example.com');
```

`authoritativeFor()` resolves the zone's `NS` records, then resolves each NS
hostname to its A/AAAA addresses. `query()` tries every authoritative IP and returns
the first answer; it throws `ResolutionFailed` only when none answer (or the zone
exposes no reachable authoritative server). You reach it from the facade via
`$dns->authoritative()`.

**SSRF safety.** Because a zone owner controls their own NS and glue records, an
NS-derived address is untrusted input. By default `authoritativeFor()` queries
**only public IPs** — RFC1918, loopback, link-local/metadata, and reserved space are
refused — and caps the NS fan-out. Pass `allowNonPublicNameservers: true` to query
a LAN/internal nameserver on purpose:

```php
$authoritative = new AuthoritativeResolver(new SocketResolver, allowNonPublicNameservers: true);
```
