---
title: Discovery
weight: 46
description: How a domain's DNS provider is found — the _domainconnect TXT record, the settings document, the template support check — and how those HTTPS requests are guarded.
---

# Discovery

`DomainConnect::discover(string $name, ?Template $template = null): Discovery`
answers two questions about a name: does its DNS provider speak Domain Connect, and
(given a template) does that provider know the template?

## The steps

1. **Find the zone.** `ZoneLocator` walks the name upward, asking for `SOA` at each
   candidate. The first candidate that answers with a `SOA` record *owned by that
   candidate* is the apex; a parent's `SOA` carried in an authority section does not
   count. `mail.acme.com` becomes the `Zone` with apex `acme.com` and host `mail`.
   No `SOA` for the name or any parent below the TLD throws `ZoneNotFound` (a
   single-label name such as `com` is never taken as an apex). An IDN is walked in
   its punycode form, so the `Zone` is always ASCII: `mail.blåbær.dk` becomes apex
   `xn--blbr-roah.dk`, host `mail`.
2. **Read `_domainconnect.<apex>`.** The first TXT value names the provider's
   Domain Connect endpoint. It may be a host, `host:port`, `host/path`, or the same
   with an `https://` prefix. No record means no settings — the most common case.
3. **Fetch the settings document** at `https://<value>/v2/<apex>/settings` and read
   it into `ProviderSettings` (`providerId`, `providerName`, `urlSyncUX`,
   `urlAsyncUX`, `urlAPI`, `urlControlPanel`, `width`, `height`, `nameServers`).
   Each URL field, when present, must be plain `https` (a host; no userinfo, query
   or fragment); a document with any other URL — `javascript:…`, `http://…`, a
   base carrying `?` — is refused like a malformed one, so `settings` is `null`.
4. **Check template support** (only with a template and a `urlAPI`):
   `GET {urlAPI}/v2/domainTemplates/providers/{providerId}/services/{serviceId}`.
   A `urlAPI` (or `urlSyncUX`) that already ends in `/v2` is not given a second one.
   A `2xx` means supported, a `404` means not supported, anything else leaves it
   unknown.

## The `Discovery` object

| Member | Meaning |
| --- | --- |
| `zone` | The `Zone` (apex + host) the name belongs to. |
| `settings` | The provider's `ProviderSettings`, or `null`. |
| `supported` | `true` / `false` from the support check, or `null` when it did not run or gave no clear answer. |
| `checkedAt` | When the discovery ran (`DateTimeImmutable`). |
| `isAvailable()` | The provider speaks Domain Connect **and** publishes `urlSyncUX` (the synchronous flow). |
| `supportsTemplate()` | `supported === true`. |
| `toArray()` / `fromArray()` | A storable form, so an application can keep the result. |

### "Not available" and "not supported" are different answers

- **Not available** (`settings` is `null`, or `isAvailable()` is `false`): there is
  no `_domainconnect` record, the settings request failed or returned something
  other than a `2xx` JSON object, the document is missing `providerId` /
  `providerName` or carries a URL that is not plain `https`, or the provider has no
  synchronous flow. Show the customer the
  records to add by hand.
- **Not supported** (`supported === false`): the provider speaks Domain Connect but
  answered `404` for your template. That is expected until the provider has onboarded
  the template from the public repository.
- **Unknown** (`supported === null`): no template was passed, the provider published
  no `urlAPI`, the `urlAPI` host failed the checks below, or the support request
  failed or returned another status. Treat it as "do not offer the button".

## Guarding the requests

The `_domainconnect` value is written by whoever controls the zone, and `urlAPI`
comes from a document fetched from that value. Both are untrusted, so both URLs are
checked before any request is made:

- **HTTPS only.** A value with any other scheme, or with whitespace, is refused.
- **Plain URLs only.** No userinfo, no query, no fragment; the host must be a
  hostname (`[A-Za-z0-9.-]`) or an IP literal (IPv6 in brackets). The URL is parsed
  with `parse_url()`, as `StreamTransport` does when it pins the request.
- **Public addresses only.** The host's `A` and `AAAA` records are looked up and
  **every** address must be globally routable — private, loopback, link-local,
  CGNAT and other reserved ranges are refused, with the same address filter the
  [authoritative resolver](../security/_index.md) uses for nameservers. An IP
  literal is checked the same way.
- **Fail closed.** If either address lookup fails, or the host has no address, no
  request is made.
- **Pinned.** The request goes to the address that passed the check (an `A` record
  is preferred over `AAAA`), via `Transport::get($url, $resolvedIp)`. The default
  `StreamTransport` connects to that IP, sends the original `Host` header, and
  verifies the TLS certificate against the original host name (`peer_name`). This
  closes the gap between "checked the name" and "connected to the name", where a
  second lookup could return a different, internal address.
- **No redirects.** `StreamTransport` does not follow redirects.
- **Bounded.** `StreamTransport` gives up after its timeout (5 seconds by default)
  for the whole request, and refuses — status `0`, not a truncated body — a
  response body over 64 KiB.

A settings host that fails these checks throws `DiscoveryRefused` (a
`DnsException`): the zone points somewhere that will not be fetched, and you
probably want to log it. A `urlAPI` that fails them only leaves `supported` as
`null` — the provider was already found.

### Honest limits

- **The pinning is only as good as the transport.** A custom `Transport` that
  ignores `$resolvedIp` and resolves the host again gives up the SSRF protection.
  If you write one, connect to `$resolvedIp` and verify TLS against the URL's host.
- **Any port is accepted** on a host that passes the public-address check
  (`dc.example.com:8443` is fine).
- **`allowNonPublicHosts`** turns the address check and the pinning off. It exists
  for local testing against a provider on your own network. On the facade it is the
  fourth argument of `Dns::domainConnect(..., allowNonPublicHosts: true)` and is
  independent of `allowNonPublicNameservers`: allowing internal nameservers does not
  allow internal Domain Connect hosts. The `InteractsWithDomainConnect` test helper
  turns it on. Do not enable it in production.
- Discovery lookups go through the facade's resolver (recursive by default), not
  the authoritative nameservers.
