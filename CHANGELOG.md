# Changelog

All notable changes to `cboxdk/dns` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-14

Initial public release.

### Added

- **Zero-dependency socket resolver** (`SocketResolver`) — speaks DNS over UDP with
  an automatic TCP retry on truncation (RFC 1035), targeting any nameserver with
  recursion and the EDNS0 DO bit toggleable. No external `dig` binary, no runtime
  dependencies.
- **DNS-over-HTTPS resolver** (`HttpsResolver`) — the Google/Cloudflare JSON API
  behind the shared `Resolver` contract, with an injectable HTTP fetcher so tests
  never touch the network.
- **Authoritative resolver** (`AuthoritativeResolver`) — discovers a zone's NS set,
  resolves it to IPs, and reads records directly from the authoritative servers
  with recursion disabled, bypassing every recursive cache.
- **Domain-ownership verification** (`DomainVerifier`) — reads a TXT challenge at
  `_cbox-challenge.<domain>` straight from the authoritative nameservers;
  deny-by-default on any failure or mismatch.
- **Propagation checking** (`PropagationChecker`) — compares the authoritative
  record set against a panel of public recursive resolvers, reporting
  `Propagated` / `Pending` / `Misconfigured`; includes a named 15-provider registry
  (`PublicResolvers`).
- **DNSSEC chain validation** (`DnssecValidator`) — root-anchored on the IANA KSK
  DS records; walks root → TLD → zone; verifies RRSIG signatures via OpenSSL
  (RSA/ECDSA) and libsodium (Ed25519); validates DS links, NSEC/NSEC3 denial of
  existence, and wildcard no-closer-match proofs; enforces in-bailiwick signers.
  Deny-by-default: `secure` / `insecure` / `bogus`.
- **Diagnostics engine** (`Diagnostics`) — an intoDNS/MxToolbox-style catalog of
  checks (delegation, nameservers, SOA, MX/FCrDNS, SPF, DMARC, DKIM, CAA, DNSSEC,
  propagation) aggregated into a structured `Report` of severity-tagged findings.
- **`FakeResolver`** — an in-memory `Resolver` implementation, with per-nameserver
  stubs, that drives the entire library (including the DNSSEC chain walk) offline.
- **Supply-chain tooling** — `composer license-check` (permissive-license gate) and
  `composer sbom` (deterministic CycloneDX 1.5 SBOM), wired into CI alongside
  `composer audit`.

### Scope

- Live SMTP diagnostics (banner / STARTTLS / open-relay), RBL/blacklist lookups,
  and geo-distributed propagation vantage points are intentionally **out of v1**
  and tracked as roadmap; they are not stubbed.

[0.1.0]: https://github.com/cboxdk/dns/releases/tag/v0.1.0
