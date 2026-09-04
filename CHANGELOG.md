# Changelog

All notable changes to `cboxdk/dns` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-02

Stable release. No code changes since 0.1.1: this promotes the existing surface
to a versioned commitment rather than shipping anything new.

### Changed

- The public API is now covered by semantic versioning. Breaking changes require
  a 2.0.0, so consumers can depend on `^1.0` instead of pinning an exact 0.x.

### Scope

- Live SMTP diagnostics (banner / STARTTLS / open-relay), RBL/blacklist lookups,
  and geo-distributed propagation vantage points remain out of scope and are
  tracked as roadmap. They are not stubbed.

## [0.1.1] - 2026-07-15

### Added

- Documentation on performance and intended use: lookups are uncached and aimed
  at verification and debugging rather than serving as a hot-path resolver.

## [0.1.0] - 2026-07-14

Initial public release.

### Added

- **Zero-dependency socket resolver** (`SocketResolver`) — speaks DNS over UDP with
  an automatic TCP retry on truncation and a bounded UDP retry (RFC 1035), targeting
  any nameserver with recursion and the EDNS0 DO bit toggleable. Validates the
  response transaction ID and echoed question before trusting an answer (optional
  0x20 mixed-case hardening), surfaces the `RCODE`, brackets IPv6 nameserver
  literals, and punycodes IDN names. No external `dig` binary, no runtime
  dependencies. Implements `ConcurrentResolver` for batched, single-timeout polling.
- **DNS-over-HTTPS resolver** (`HttpsResolver`) — the Google/Cloudflare JSON API
  behind the shared `Resolver` contract, with an injectable HTTP fetcher so tests
  never touch the network; maps the DoH `Status` to an `Rcode` and refuses
  per-nameserver / non-recursive queries it cannot honestly serve.
- **Authoritative resolver** (`AuthoritativeResolver`) — discovers a zone's NS set,
  resolves it to IPs, and reads records directly from the authoritative servers
  with recursion disabled, bypassing every recursive cache. Queries only public
  addresses by default (SSRF-safe; `allowNonPublicNameservers` opts in) and caps the
  NS fan-out.
- **Domain-ownership verification** (`DomainVerifier`) — reads a TXT challenge
  straight from the authoritative nameservers with a constant-time (`hash_equals`)
  match; deny-by-default on any failure or mismatch. The challenge prefix
  (default `_cbox-challenge`) is configurable.
- **Propagation checking** (`PropagationChecker`) — compares the authoritative
  record set against a panel of public recursive resolvers (polled concurrently
  under one timeout budget), reporting `Propagated` / `Pending` / `Misconfigured`;
  includes a named 15-entry / 11-operator registry (`PublicResolvers`) from which
  the default panel is derived.
- **DNSSEC chain validation** (`DnssecValidator`) — root-anchored on the IANA KSK
  DS records; walks root → TLD → zone; verifies RRSIG signatures via OpenSSL
  (RSA/ECDSA) and libsodium (Ed25519); validates DS links, NSEC/NSEC3 denial of
  existence, and wildcard no-closer-match proofs; enforces in-bailiwick signers.
  Deny-by-default: `secure` / `insecure` / `bogus`.
- **Diagnostics engine** (`Diagnostics`) — an intoDNS/MxToolbox-style catalog of
  checks (delegation, nameservers, SOA, MX/FCrDNS, SPF, DMARC, DKIM, CAA, DNSSEC,
  propagation) aggregated into a structured `Report` of severity-tagged findings;
  NS discovery is memoised across a run.
- **Record types with typed access** — the full IANA registry of non-obsolete,
  non-meta types: A, AAAA, CNAME, DNAME, MX, KX, TXT, NS, SOA, PTR, HINFO, RP, CAA,
  SRV, NAPTR, CERT, LOC, SSHFP, SMIMEA, OPENPGPKEY, EUI48, EUI64, URI, TLSA, SVCB,
  HTTPS, and the DNSSEC / delegation set (DS, CDS, RRSIG, DNSKEY, CDNSKEY, NSEC,
  NSEC3, NSEC3PARAM, CSYNC, ZONEMD). `DnsRecord::data()` and `DnsResponse::data()`
  return typed `RecordData` value objects — `Address`, `Name`, `Txt`, `Mx`, `Kx`,
  `Srv`, `Soa`, `Caa`, `Naptr`, `Cert`, `Loc`, `Sshfp`, `Smimea`, `Openpgpkey`,
  `Eui`, `Uri`, `Hinfo`, `Rp`, `Cds`, `Cdnskey`, `Nsec3Param`, `Csync`, `Zonemd`,
  `Tlsa`, `Svcb` — so consumers read typed fields instead of parsing strings or
  touching raw bytes. SVCB/HTTPS SvcParams (ALPN, port, IPv4/IPv6 hints, ECH,
  mandatory, no-default-alpn) are fully parsed; a malformed compound RR degrades to
  the RFC 3597 generic form rather than failing the whole response.
- **Known TXT policies** — `Txt::spf()` / `dkim()` / `dmarc()` parse SPF, DKIM, and
  DMARC records into typed `SpfPolicy` / `DkimKey` / `DmarcPolicy` objects
  (mechanisms and qualifiers, key type/state, policy, reporting URIs, alignment).
- **CNAME chain following** (`CnameResolver`, `Dns::follow()`) — an explicit opt-in
  that follows a name's CNAME chain to its answer and returns the traversed hops
  (`ResolvedChain`: `aliases()`, `canonicalName()`, the final records). Loop-safe: a
  name is never queried twice and a chain that points back stops with a reason.
- **SPF expansion** (`SpfResolver`, `Dns::spf()`) — recursively expands a domain's
  SPF policy, following `include:` / `redirect=` and expanding `a` / `mx` into
  addresses, to the complete flattened endpoint list (`SpfEvaluation::allIp4()` /
  `allIp6()`) plus the include tree for traceability. Enforces the RFC 7208 §4.6.4
  10-lookup and void-lookup limits across the whole tree and refuses `include:`
  loops, so a hostile or misconfigured policy terminates with `exceededLookupLimit`
  / an error rather than spinning.
- **Delegation tracing** (`DelegationTracer`, `Dns::trace()` / `traceReverse()`) — a
  `dig +trace`-style walk from the root down through every zone cut, recording which
  nameserver delegated which zone (and the glue), plus reverse (in-addr.arpa /
  ip6.arpa) tracing for CIDR/reverse-zone delegation. Loop-safe: every step must
  descend towards the target, visited zones are refused, and the walk is bounded, so
  a self-referential or lame delegation terminates with a reason instead of spinning.
- **Full response sections** — `DnsResponse` now also exposes the parsed additional
  section (`->additional`, glue records) alongside the answer and authority sections.
- **`FakeResolver` + `InteractsWithDns`** — an in-memory `Resolver` (per-nameserver
  stubs, RCODE stubs, per-record TTL/priority, query recording + `assertQueried`,
  strict mode, concurrent support) and a dogfooded testing trait that drive the
  entire library (including the DNSSEC chain walk) offline.
- **Supply-chain tooling** — `composer license-check` (permissive-license gate,
  correct SPDX `AND`/`OR` handling) and `composer sbom` (deterministic CycloneDX 1.5
  SBOM), wired into CI alongside `composer audit`.

### Security

- Off-path DNS response spoofing on the authoritative-read path is closed by
  transaction-ID and question-echo validation (previously the ID was unchecked).
- Server-Side Request Forgery via attacker-controlled NS/glue records is closed by
  default public-address filtering in `AuthoritativeResolver`.
- Wire-name encoding rejects embedded NUL octets, empty interior labels, and names
  over 255 octets; the message reader rejects forward/looping compression pointers.
- A pre-release adversarial DNSSEC review found and fixed a cross-zone forgery
  bypass (now covered by strict in-bailiwick enforcement and a regression test).

### Scope

- Live SMTP diagnostics (banner / STARTTLS / open-relay), RBL/blacklist lookups,
  and geo-distributed propagation vantage points are intentionally **out of v1**
  and tracked as roadmap; they are not stubbed.

[1.0.0]: https://github.com/cboxdk/dns/releases/tag/v1.0.0
[0.1.1]: https://github.com/cboxdk/dns/releases/tag/v0.1.1
[0.1.0]: https://github.com/cboxdk/dns/releases/tag/v0.1.0
