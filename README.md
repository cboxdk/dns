# cboxdk/dns

A zero-runtime-dependency DNS toolkit for PHP 8.4+. It speaks the DNS wire
protocol over raw sockets, so it can read a zone's answer **from the zone's own
authoritative nameservers** — not from whatever a recursive resolver happens to
have cached. That distinction is the whole point: it is what makes domain-ownership
verification and propagation checks trustworthy.

On top of that resolver it ships domain verification, authoritative-vs-recursive
propagation checking, a full DNSSEC chain validator, and an intoDNS/MxToolbox-style
diagnostics engine — all framework-agnostic, all driven through one contract you
can fake in tests.

```bash
composer require cboxdk/dns
```

## Why this exists

- **Reliable domain verification.** The usual "look up our TXT token" check goes
  through a recursive resolver, whose cache can be stale (a just-published record
  is invisible until the old negative TTL expires) or, on a shared resolver, even
  poisoned. This library discovers a zone's authoritative nameservers and queries
  the TXT record **directly against them with recursion disabled**, so a match
  means the record is really published — right now, at the source of truth.

- **DNSSEC validation without a black box.** There is no vetted, maintained PHP
  library to wrap for DNSSEC chain validation. Rather than trust a resolver's `AD`
  bit (which only tells you *someone else* validated), this package walks the chain
  itself — root → TLD → zone — and checks every signature. The protocol work
  (canonical form, key/signature encoding, validity windows, NSEC/NSEC3 denial
  proofs) is ours; the **signature math is delegated to OpenSSL (RSA/ECDSA) and
  libsodium (Ed25519)** — never hand-rolled. The module is built against real
  captured signed-zone vectors and was adversarially reviewed (a cross-zone
  forgery bypass was found and fixed before release — see [`SECURITY.md`](SECURITY.md)).

- **Zero runtime dependencies.** The whole thing runs on `ext-sockets` and the
  standard library. Nothing to audit downstream, nothing to keep patched, no
  `dig` binary shelled out to.

## Quickstart

Every example below uses the real facade, `Cbox\Dns\Dns`.

### Look a record up

```php
use Cbox\Dns\Dns;
use Cbox\Dns\Enums\RecordType;

$dns = new Dns;

$response = $dns->lookup('example.com', RecordType::MX);

foreach ($response->records as $record) {
    echo "{$record->priority} {$record->value}\n";
}

// Or just the values:
$response->values();          // ['mail.example.com', ...]
$response->contains('mail.example.com');
```

### Verify domain ownership (authoritatively)

```php
$dns = new Dns;

// Tell the user where to publish the token:
$dns->challengeHost('example.com');   // "_cbox-challenge.example.com"

// Then check it — read straight from example.com's authoritative NS:
if ($dns->verifyDomain('example.com', 'my-verification-token')) {
    // Ownership proven. Deny-by-default: any failure or mismatch returns false.
}
```

### Check propagation

```php
use Cbox\Dns\Propagation\PropagationStatus;

$report = $dns->checkPropagation('www.example.com', RecordType::A, 'example.com');

$report->status;               // PropagationStatus::Propagated | Pending | Misconfigured
$report->authoritativeValues;  // the source-of-truth answer
$report->stale();              // the public resolvers that haven't caught up yet
```

### Validate the DNSSEC chain

```php
$result = $dns->dnssec()->validate('cloudflare.com');

$result->status->value;   // "secure" | "insecure" | "bogus"
$result->isSecure();      // true only on a complete, anchored chain
$result->reason;          // human-readable explanation

// Or validate one record set (answer or authenticated denial of existence):
$dns->dnssec()->validateRecords('www.cloudflare.com', RecordType::A);
```

`secure` means a full chain from the IANA root anchors verified. `insecure` means
the zone is *provably* unsigned (an authenticated NSEC/NSEC3 proof). Everything
else — a broken DS link, a bad or expired signature, an unknown algorithm — is
`bogus`. There is no silent pass.

### Run a full health check

```php
$report = $dns->diagnose('example.com');

$report->passed();     // clean bill: no errors and no warnings
$report->hasErrors();

foreach ($report->findings as $finding) {
    echo "[{$finding->severity->value}] {$finding->category}: {$finding->message}\n";
}
```

## Features

- **Zero-dependency socket resolver** — DNS over UDP with automatic TCP retry on
  truncation (RFC 1035) and a bounded UDP retry. Target any nameserver; recursion
  toggleable. Every response is checked against the query's transaction ID **and**
  echoed question before it is trusted (optional 0x20 mixed-case hardening), so an
  off-path spoofed answer is rejected. The `RCODE` is surfaced, so NXDOMAIN, NODATA,
  and SERVFAIL are distinguishable — not collapsed into "empty". IPv6 nameservers
  and internationalized (IDN/punycode) names are handled.
- **DNS-over-HTTPS (DoH)** — the Google/Cloudflare JSON API, behind the same
  `Resolver` contract, with an injectable fetcher (no network in tests). Refuses
  authoritative/per-nameserver queries it cannot honestly serve.
- **Authoritative resolver** — discovers a zone's NS set, resolves it to IPs, and
  reads records directly from the source, bypassing every recursive cache. The
  NS set is attacker-influenced, so **only public addresses are queried by default**
  (SSRF-safe; `allowNonPublicNameservers` opts into LAN/internal servers), and the
  fan-out is capped.
- **Domain-ownership verification** — TXT challenge read authoritatively,
  constant-time (`hash_equals`) match, deny-by-default. The challenge prefix is
  configurable (no forced cbox-branded record).
- **Propagation checking** — authoritative record set vs. a panel of public
  recursive resolvers (polled **concurrently** under one timeout), plus a named
  15-entry / 11-operator registry.
- **DNSSEC chain validation** — root-anchored, RRSIG via OpenSSL, Ed25519 via
  libsodium, DS links, NSEC/NSEC3 denial-of-existence, wildcard proofs, in-bailiwick
  enforcement. Deny-by-default.
- **Diagnostics engine** — delegation, nameservers, SOA, MX/FCrDNS, SPF, DMARC,
  DKIM, CAA, DNSSEC, and propagation checks, aggregated into a structured report.
  NS discovery is memoised across the run.
- **Typed records, no raw parsing** — A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, CAA,
  SRV, NAPTR, CERT, LOC, SSHFP, SMIMEA, OPENPGPKEY, URI, TLSA, SVCB, HTTPS, and the
  DNSSEC set. Call `$record->data()` for a typed value object (`Address`, `Mx`,
  `Srv`, `Soa`, `Caa`, `Naptr`, `Cert`, `Loc`, `Sshfp`, `Smimea`, `Openpgpkey`,
  `Uri`, `Tlsa`, `Svcb`) and read `->preference`, `->serial`, `->alpn`, `->ipv4hint`,
  `->latitude` directly — SVCB/HTTPS SvcParams (ALPN, port, IPv4/IPv6 hints, ECH,
  mandatory) are fully parsed, never a hex blob.
- **Known TXT policies** — a TXT record's `->data()` (`Txt`) parses SPF, DKIM, and
  DMARC on demand: `$txt->spf()`, `$txt->dkim()`, `$txt->dmarc()` return typed
  `SpfPolicy` / `DkimKey` / `DmarcPolicy` objects (mechanisms, key state, policy,
  reporting URIs, alignment) or null when the text isn't that policy.
- **CNAME following & SPF expansion** — `$dns->follow('www.example.com', RecordType::A)`
  follows the CNAME chain and returns the traversed hops and canonical name;
  `$dns->spf('example.com')` recursively expands SPF (`include:` / `redirect=` / `a`
  / `mx`) into the complete flattened `allIp4()` / `allIp6()` endpoint list plus the
  include tree. Both are loop-safe and bounded (SPF enforces the RFC 7208 10-lookup
  limit).
- **Delegation tracing** — `$dns->trace('www.example.com')` walks the delegation
  from the root down (`dig +trace`-style), recording each zone cut, which nameserver
  delegated it, and the glue; `$dns->traceReverse('8.8.8.8')` traces the reverse
  (in-addr.arpa) chain for CIDR/reverse-zone delegation. Loop-safe by construction.
- **Testable by construction** — everything resolves through the `Resolver`
  contract; `Cbox\Dns\Testing\FakeResolver` (with per-nameserver stubs, RCODE stubs,
  query recording, and strict mode) and the `InteractsWithDns` trait drive the
  entire library — including the DNSSEC chain walk — offline.

## Requirements

- **PHP 8.4+**
- **`ext-sockets`** (enforced) — the raw resolver transport.
- **`ext-openssl` and `ext-sodium`** — required only by the DNSSEC module (RSA/ECDSA
  and Ed25519 signature verification respectively). Both ship with a stock PHP
  build; they are not hard Composer constraints because the resolver, verification,
  propagation, and non-DNSSEC diagnostics work without them.
- **`ext-intl`** — needed only to look up an internationalized (IDN) domain name;
  an ASCII name works without it. Suggested, not required.

No Laravel, no framework. See [`docs/requirements.md`](docs/requirements.md).

## Scope and roadmap

This is a **DNS-only** library, and honest about it:

- **In v1:** everything in the feature list above.
- **Out of v1 (roadmap, deliberately not stubbed):**
  - **Live SMTP diagnostics** (banner / STARTTLS / open-relay probing) — needs
    outbound mail-port egress.
  - **RBL / blacklist lookups** — needs third-party list infrastructure.
  - **Geo-distributed propagation.** The propagation check is a *cache-diversity*
    signal across independent recursive operators queried from one host — every
    major provider is anycast, so you sample operators, not locations. True
    geographic vantage points (regional DoH probes) are a roadmap item, not a claim
    made here. The reliable signal is the authoritative-vs-recursive diff.

## Documentation

Full docs live in [`docs/`](docs/index.md): a [quickstart](docs/quickstart.md),
[core concepts](docs/core-concepts/_index.md) (resolvers, verification,
propagation, architecture), the [DNSSEC](docs/dnssec/_index.md) validation and
threat model, the [diagnostics](docs/diagnostics/_index.md) check catalog, a
[cookbook](docs/cookbook/_index.md), and the [security](docs/security/_index.md)
posture.

## Security

Report vulnerabilities through **GitHub Private Vulnerability Reporting** — see
[`SECURITY.md`](SECURITY.md), which also documents the DNSSEC security posture.

## License

MIT — see [`LICENSE`](LICENSE).
