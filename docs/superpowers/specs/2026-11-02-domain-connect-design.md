# Domain Connect: one-click DNS setup for Cbox products

Date: 2026-11-02. Status: proposed. Spans three repos: `cboxdk/dns` (core),
`cboxdk/laravel-dns` (Laravel wiring), `cbox-engage` (first consumer). Decided in
chat on 2026-11-02: no new `laravel-domain` package; one `providerId` (`cbox.dk`)
with one template per product.

## Why

Adding a sending domain to Engage today means copying four DNS records by hand,
getting the proxy flag right at Cloudflare, and waiting. Most customers get at least
one record wrong the first time. Domain Connect is the open protocol (IETF draft
`draft-ietf-dconn-domainconnect`) that lets a service provider hand the customer's
DNS host a template to apply: the customer signs in at their DNS host, approves, and
the records land. Eleven DNS providers run it, among them Cloudflare, GoDaddy, IONOS,
Simply.com, Vercel and WordPress.com. One implementation covers all of them, and
every later Cbox product (ID custom domains, Sites custom domains) reuses it by
adding a template.

Out of scope here: the asynchronous OAuth flow (needs a client secret registered
with each DNS provider; nothing we need yet), templates for ID and Sites (same
mechanism, separate PRs once this one is merged), any UI in the libraries.

## What the customer sees (Engage)

1. Settings → Domains → **Add domain**. Engage registers the domain with Resend as
   today and gets the DKIM key and MX host back.
2. Engage looks the domain up: does its DNS host speak Domain Connect, and does it
   know the `cbox.dk` / `engage-sending` template? If yes, the domain row shows
   **Auto configure** next to the record table. If no, the row looks as it does
   today (manual records).
3. **Auto configure** sends the customer to their DNS host (Cloudflare etc.) with a
   signed URL. They sign in, see "Cbox Engage wants to add these records", approve.
4. The DNS host sends them back to `cboxengage.com`. Engage re-verifies at once,
   then again after 1, 5 and 15 minutes, and the usual ten-minute re-check keeps
   going until the domain is verified. The flash says what happened, including a
   plain "you cancelled at Cloudflare" when the host reports `access_denied`.
5. DMARC is included in the template only when the domain has no DMARC record yet
   (a template group the request opts into). An existing policy is never replaced.

## Design

### Layering

```
cboxdk/dns            Cbox\Dns\DomainConnect\*     protocol, no framework, no HTTP library
cboxdk/laravel-dns    Cbox\LaravelDns\*            config, container bindings, facade, commands, fake
cbox-engage           App\Messaging\SendingDomains  the button, the callback route, the re-check
Domain-Connect/Templates (GitHub)                   cbox.dk.engage-sending.json, reviewed by maintainers
```

Core stays zero-dependency: the settings and support calls are plain HTTPS GETs
through the same `callable(string $url): ?string` transport seam `HttpsResolver`
already uses, so a host can swap it and tests need no network.

### Core: `Cbox\Dns\DomainConnect`

**Value objects** (readonly, `fromArray` at the JSON edge only):

- `Template` — `providerId`, `providerName`, `serviceId`, `serviceName`, `version`,
  `syncPubKeyDomain`, `syncRedirectDomain`, `records: list<TemplateRecord>`. Loads
  the exact JSON we publish; a test in `cbox-engage` asserts the committed template
  file round-trips through it, so the code and the published template cannot drift.
- `TemplateRecord` — `type: TemplateRecordType` (enum: A, AAAA, CNAME, NS, TXT, MX,
  SRV, SPFM, APEXCNAME), `host`, `pointsTo`/`data`/`spfRules`, `ttl`, `priority`,
  `groupId`, `essential`, `txtConflictMatchingMode`. Variables are `%name%`.
- `ProviderSettings` — the DNS host's `/v2/{domain}/settings` answer: `providerId`,
  `providerName`, `urlSyncUX`, `urlAsyncUX`, `urlAPI`, `urlControlPanel`,
  `width`/`height`, `nameServers`.
- `Zone` — `apex` + `host` (the labels below the apex, empty for the apex itself).
  `mail.example.com` → apex `example.com`, host `mail`.
- `Discovery` — the result of looking a domain up: `zone`, `settings` (null when the
  host does not speak Domain Connect), `supported` (null until the template check
  ran, then bool), `checkedAt`.
- `ApplyRequest` — what we send: `template`, `zone`, `variables: array<string,string>`,
  `groupIds: list<string>`, `redirectUri`, `state`.
- `ApplyOutcome` — what the callback gives back: `state`, `error` (OAuth-style
  string or null), `errorDescription`. `succeeded()` is "no error". The DNS host
  does not tell us the records are live; only DNS does.
- `RecordSet` — the concrete records a template produces for a zone + variables +
  groups: `list<ExpectedRecord>` with fully-qualified names. This is the single
  source for "what should be in DNS", used by Auto configure, by the manual
  record table, and by the check below.

**Services** (one job each, contract-first):

- `ZoneLocator::locate(string $name): Zone` — walks the name upward querying SOA
  authoritatively until the SOA owner equals the candidate; that is the apex.
  Deny-by-default: no SOA found → `DnsException`.
- `Discoverer::discover(string $name, ?Template $template = null): Discovery` —
  TXT `_domainconnect.<apex>` → `https://<value>/v2/<apex>/settings` →
  `ProviderSettings`; with a template, also
  `GET {urlAPI}/v2/domainTemplates/providers/{providerId}/services/{serviceId}`
  (2xx → supported, 404 → not). The settings URL is only ever built from the TXT
  value, is HTTPS only, and runs through the same public-address SSRF guard the
  resolvers use: a `_domainconnect` TXT pointing at a private address is refused.
- `SyncUrlBuilder::build(ApplyRequest, ProviderSettings, Signer, string $keyHost): string`
  — `{urlSyncUX}/v2/domainTemplates/providers/{providerId}/services/{serviceId}/apply?`
  with `domain`, `host` (omitted for the apex), `redirect_uri`, `state`, the
  variables, `groupId` (comma-joined) — URL-encoded, then `sig` over the full query
  string excluding `sig` and `key`, and `key=<keyHost>` appended. Variable names are
  validated against the template; an unknown or missing variable is an exception,
  never a URL with `%dkim%` still in it.
- `Contracts\Signer::sign(string $query): string` — returns the base64 signature.
  `OpenSslRs256Signer` wraps `openssl_sign` with `OPENSSL_ALGO_SHA256` on an RSA
  private key (PEM). Algorithm pinned; nothing hand-rolled.
- `PublicKeyRecords::for(string $publicKeyPem): list<string>` — the TXT strings to
  publish at `_dcpubkeyv1.<syncPubKeyDomain>`: `p=<n>,a=RS256,d=<chunk>` where the
  chunks are the base64 DER SubjectPublicKeyInfo split to stay under 255 bytes per
  string. Used by the Artisan command below, and by the test that proves the
  signer and the published key agree.
- `CallbackParser::parse(array $query): ApplyOutcome` — reads `state`, `error`,
  `error_description` from the redirect back. State validation is the app's job
  (it knows what it issued).
- `RecordSetCheck` — a `Diagnostics\Contracts\Check` that compares a `RecordSet`
  against authoritative DNS and emits one `Finding` per record: present, missing,
  or mismatched (with the live value). SPFM compares by "the zone's SPF contains
  `spfRules`", not by exact match, as the spec asks. Runs through the existing
  `Diagnostics::runWith()`, so the result is the `Report` every consumer already knows.

**Testing/** — `FakeTransport` (map of URL → body/status, strict mode throws on
unstubbed URLs), `FakeSigner` (deterministic `sig`), and `InteractsWithDomainConnect`
composing both with `InteractsWithDns`. The core's own tests use them.

**Real vectors.** `OpenSslRs256Signer` is tested with a committed 2048-bit test
keypair: sign the spec's example query string
`a=1&b=2&ip=10.10.10.10&domain=example.net`, then verify the signature with
`openssl_verify` against the key rebuilt from `PublicKeyRecords::for()`. A second
test cross-checks against a signature produced by the reference Python
`domainconnect` library for the same key and query, committed as a fixture, so our
encoding matches what DNS providers actually verify.

### Laravel: `cboxdk/laravel-dns`

Config, `config/dns.php` → `domain_connect`:

| Key | Env | Default | Purpose |
|-----|-----|---------|---------|
| `provider_id` | `DNS_DOMAIN_CONNECT_PROVIDER_ID` | `null` | Our identity in templates, `cbox.dk` for Cbox products. Required to build URLs. |
| `private_key` | `DNS_DOMAIN_CONNECT_PRIVATE_KEY` | `null` | RSA private key, PEM (newlines as `\n` in env). Required to sign. |
| `key_host` | `DNS_DOMAIN_CONNECT_KEY_HOST` | `_dcpubkeyv1` | Label of the public-key TXT under `syncPubKeyDomain`. Rotation = publish `_dcpubkeyv2`, change this. |
| `http_timeout` | `DNS_DOMAIN_CONNECT_TIMEOUT` | `5.0` | Settings/support calls. |

`DnsConfig` gets a typed `DomainConnectConfig` sub-object. Bindings: `Signer`
(the OpenSSL one when a key is configured, otherwise a `RefusingSigner` that throws
with a message naming the env key), `Discoverer`, `ZoneLocator`, and a
`DomainConnect` front door with `discover()`, `applyUrl()`, `recordSet()`,
`check()`, `callback()`. Facade: `Dns::domainConnect()`.

Commands:

- `dns:domain-connect:discover {name} [--template=path]` — prints zone, provider,
  URLs, supported yes/no. The first thing to run when a customer says the button
  is missing.
- `dns:domain-connect:keys` — prints the TXT records for the configured private
  key, ready to paste at `_dcpubkeyv1.cbox.dk`. Also `--verify` to read the live
  TXT back and confirm it matches the configured key.
- `dns:domain-connect:url {template} {name} {--var=k=v}*` — builds a signed apply
  URL for debugging.

`Testing\InteractsWithDns` gains `fakeDomainConnect()` swapping transport and
signer in the container, so an app test can stub "example.com is at Cloudflare and
supports engage-sending" and assert on the URL it redirected to.

No routes and no views: a library ships primitives. The callback route lives in the
app.

### Engage

- `composer require cboxdk/laravel-dns`. The existing `DnsResolver` contract and
  `Dmarc` reader stay as they are; this change does not refactor them.
- `sending_domains` gets a `domain_connect` JSON column holding the serialized
  `Discovery` (provider name, sync URL, supported, checked at). Written by
  `SendingDomains::register()` right after the provider call, refreshed by
  `VerifyDomains` when older than a day, and null when discovery failed.
  Discovery is a TXT lookup plus one or two HTTPS calls; it must never block a
  page render.
- `SendingDomains::autoConfigureUrl(SendingDomain, User): string` builds the
  `ApplyRequest`: variables `mx` (Resend's MX value) and `dkim` (Resend's DKIM
  value with the leading `p=` stripped, because the template fixes the prefix);
  groups `sending` always and `dmarc` only when `dmarc_status` is `missing`;
  `redirect_uri` the organization's callback route; `state` a signed, expiring
  token (Laravel `Crypt`, 15 minutes) carrying the domain id and user id.
- Routes: `POST organizations/{org}/domains/{domain}/auto-configure` (gate
  `manage-data`, redirects to the apply URL), `GET organizations/{org}/domains/connect/callback`
  (validates state, records `sending_domain.auto_configure_returned` with the
  outcome on the audit trail, runs `verify()`, dispatches `ReverifySendingDomain`
  delayed 1/5/15 minutes, flashes). Both thin: input → service → response.
- Domains page: an **Auto configure** button on a row whose
  `domain_connect.supported` is true and which is not yet verified for marketing,
  with the provider name in the label ("Set up at Cloudflare"). The manual table
  stays visible; the button is an addition, not a mode.
- Audit events: `sending_domain.auto_configure_started`,
  `sending_domain.auto_configure_returned` (`error` when present). Engage
  product events through the existing Engage connector are not added here.

### The template

File `cbox.dk.engage-sending.json` in `Domain-Connect/Templates`, also committed
verbatim at `cbox-engage/resources/domain-connect/cbox.dk.engage-sending.json`
(the round-trip test reads it).

```json
{
  "providerId": "cbox.dk",
  "providerName": "Cbox Engage",
  "serviceId": "engage-sending",
  "serviceName": "Email sending for Cbox Engage",
  "version": 1,
  "logoUrl": "https://cbox.dk/brand/engage-mark.svg",
  "description": "Lets Cbox Engage send email from your domain: DKIM, and SPF plus bounce handling on the send. subdomain. Your website and your existing mailboxes are not changed. Optionally adds a DMARC policy when you have none.",
  "syncBlock": false,
  "syncPubKeyDomain": "cbox.dk",
  "syncRedirectDomain": "cboxengage.com",
  "variableDescription": "%mx%: the bounce-handling mail host issued for your domain. %dkim%: the DKIM public key issued for your domain.",
  "records": [
    { "groupId": "sending", "type": "MX",   "host": "send", "pointsTo": "%mx%", "priority": 10, "ttl": 3600 },
    { "groupId": "sending", "type": "SPFM", "host": "send", "spfRules": "include:amazonses.com" },
    { "groupId": "sending", "type": "TXT",  "host": "resend._domainkey", "data": "p=%dkim%", "ttl": 3600, "txtConflictMatchingMode": "All" },
    { "groupId": "dmarc",   "type": "TXT",  "host": "_dmarc", "data": "v=DMARC1; p=quarantine", "ttl": 3600, "txtConflictMatchingMode": "Prefix", "txtConflictMatchingPrefix": "v=DMARC1", "essential": "OnApply" }
  ]
}
```

Why these choices:

- `syncRedirectDomain` is set even though every request is signed: the template
  linter requires it when `redirect_uri` is used, and it costs nothing. Engage's
  callback is on `cboxengage.com`; a future ID template says `cboxid.com`.
- `syncPubKeyDomain: cbox.dk` for every Cbox template: one key, one TXT record,
  one place to rotate.
- `p=%dkim%` not `%dkim%`: the repo rules want a fixed prefix on TXT variables.
- The DKIM record replaces any existing `resend._domainkey` TXT (`All`): there
  can only be one, and ours is the right one.
- DMARC sits in its own group with `OnApply`, so a customer can tune the policy
  later without Cloudflare treating the template as broken, and Engage only asks
  for the group when no `v=DMARC1` record exists. `p=quarantine` matches
  `Dmarc::suggestedRecord()` in Engage.
- Resend's click-tracking CNAME is not included; Engage serves tracking from its
  own host (`TrackingHost`), which is outside this template.
- No `hostRequired`, no `multiInstance`: applied once, to the apex or a subdomain.

Submission: test in the Domain Connect online editor for apex and `host` cases,
run `dc-template-linter -merge-or-fail` and `-tolerate warn` locally, open the PR
with the repo's PR template and the editor link. A clean linter run gets the
`automerge-possible` label; anything else waits for maintainers.

### Keys and DNS (operator work, through cbox-infra)

1. Generate one RSA 2048 keypair for Domain Connect. Private key into the Engage
   namespace secrets as `DNS_DOMAIN_CONNECT_PRIVATE_KEY`; later products get the
   same key.
2. Publish `php artisan dns:domain-connect:keys` output as TXT at
   `_dcpubkeyv1.cbox.dk`. Confirm with `--verify`.
3. Decide the logo URL (the template above assumes `https://cbox.dk/brand/engage-mark.svg`) and make sure it
   is reachable; the linter checks it.

The spec allows one key host per request, so rotation is: publish `_dcpubkeyv2`,
flip `key_host`, remove `v1` a week later.

## Error handling

| Situation | Behaviour |
|-----------|-----------|
| No `_domainconnect` TXT, or settings call fails/404 | `Discovery.settings = null`; button hidden; manual table as today. Logged at info, not warning: most of the internet is like this. |
| TXT present but points at a private address or non-HTTPS | Refused by the SSRF guard; treated as "not supported"; logged at warning with the host. |
| Provider speaks Domain Connect, template unknown (404 on support check) | `supported = false`; button hidden. Expected until each provider has onboarded the template. |
| Private key missing in the app | `RefusingSigner` throws on URL build; the Engage route returns a 500 with the env key in the log, never a half-built URL. |
| Customer cancels at the DNS host | Callback with `error=access_denied`: flash "You cancelled at Cloudflare; the records were not added", audit records the error, no re-verify scheduled. |
| State invalid or expired | 403, nothing recorded. |
| Callback OK but records not visible yet | Normal: flash "Records added; verifying", re-verify jobs run; the ten-minute command carries on. |
| Zone walk finds no SOA | `DnsException` from `ZoneLocator`; discovery stored as failed, button hidden. |

## Testing

- Core: Pest, no network. `FakeResolver` stubs `_domainconnect` and SOA records,
  `FakeTransport` stubs settings/support bodies. Signer tests use the committed
  keypair and the reference-library fixture. `SyncUrlBuilder` tests assert the
  exact query string order and encoding, a missing variable throws, `host` is
  absent for the apex, and `sig`/`key` come last.
- laravel-dns: Testbench feature tests for the three commands, the facade, the
  config object, the refusing signer, and `fakeDomainConnect()`; `ArchTest` keeps
  the openness policy.
- Engage: feature tests for register storing discovery, the button appearing only
  when supported and unverified, the auto-configure route redirecting to a URL
  whose `domain`/`host`/`groupId`/`sig` are as expected, the callback with and
  without `error`, expired state → 403, and the template round-trip test.
- Manual, before release: a real zone Cbox owns at Cloudflare, end to end, once
  Cloudflare has the merged template.

## Rollout

1. `cboxdk/dns` 1.x minor: `DomainConnect` module. Docs: `docs/domain-connect/`
   with `_index.md`, `discovery.md`, `signing.md`, `templates.md`, `testing.md`.
2. `cboxdk/laravel-dns` minor: config, bindings, commands, fake; docs page
   `docs/domain-connect/` with `_index.md` and `usage.md` (a folder even for one file, per the package standards).
3. Template PR opened in parallel with step 1 (it is the long pole).
4. Keys generated and TXT published (cbox-infra handoff).
5. Engage: dependency, migration, service, routes, page, tests. Ships behind the
   `supported` flag, so it is inert until a provider knows the template.
6. After the first provider onboards: manual end-to-end test, then announce.

Effort: core about 2 days, laravel-dns half a day, Engage 1 day, template and
keys half a day. Review time on the template PR is outside our control.

## Open points

- Signature byte encoding: the spec shows base64 `sig=` but does not name the
  variant. The reference library uses standard base64, URL-encoded. The fixture
  test pins this; if a provider rejects a signature during the manual test, this
  is the first thing to check.
- Whether Cloudflare picks templates up from the public repository automatically
  or needs a separate onboarding step is not documented. Check with Cloudflare
  after the PR is merged, before announcing.
- Simply.com is on the live list, which matters for Danish customers. Verify with
  a Simply.com zone in the manual test as well.
