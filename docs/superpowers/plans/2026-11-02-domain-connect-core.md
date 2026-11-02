# Domain Connect core (`cboxdk/dns`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `Cbox\Dns\DomainConnect` module that discovers whether a domain's DNS host speaks Domain Connect, builds a signed synchronous apply URL for a template, parses the redirect back, and checks the template's records against live DNS.

**Architecture:** Readonly value objects at the JSON edge (`Template`, `ProviderSettings`, `Discovery`, `RecordSet`), one service per job (`ZoneLocator`, `Discoverer`, `SyncUrlBuilder`, `RecordSetCheck`), contracts for the two things a host swaps (`Transport`, `Signer`), and a `DomainConnect` front door that composes them. HTTP goes through a `Transport` contract with a stream-based default so the library stays zero-dependency and tests never touch the network. Signing wraps `openssl_sign` with SHA-256 pinned.

**Tech Stack:** PHP 8.4, ext-openssl (signing), Pest 3/4, PHPStan level max, Pint. No new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-11-02-domain-connect-design.md`

**Plan 1 of 3.** Plan 2 (`laravel-dns`) and plan 3 (`cbox-engage`) consume the interfaces this plan produces; they live in those repos.

## Global Constraints

- PHP `^8.4`; `declare(strict_types=1)` in every file; no feature unavailable in 8.4.
- Zero runtime dependencies. `ext-openssl` becomes a hard requirement only for `OpenSslRs256Signer`; everything else works without it (keep it in `suggest`, and make the signer throw a clear `RuntimeException` when the extension is missing).
- Plain `class` / `readonly class`; no `final` (this package's openness policy). Enums are fine.
- PHPStan level max over `src` and `tests/Fixtures`: no ignores, no baselines, no inline `@var` overrides.
- Deny-by-default: unresolved zone, non-public discovery host, unknown variable, missing variable, missing sync URL are all exceptions or "not supported", never a guess.
- Variable syntax in templates is `%name%`. TXT variables in our templates carry a fixed prefix (e.g. `p=%dkim%`).
- Signature: SHA-256 with RSA PKCS#1 v1.5 (`openssl_sign` + `OPENSSL_ALGO_SHA256`), standard base64, URL-encoded as the `sig` query parameter, over the URL-encoded query string excluding `sig` and `key`. `key` is the TXT host label, default `_dcpubkeyv1`.
- Public key TXT record strings: `p=<n>,a=RS256,d=<chunk>`, chunks of the base64 DER SubjectPublicKeyInfo, each string at most 255 bytes.
- Docs follow the topic-folder layout with `_index.md` and `title`/`weight`/`description` frontmatter on every file.
- Commit after each task with a conventional-commit subject; the verification gate (`composer qa`) must be green before each commit.

## Review Focus

- A `_domainconnect` TXT whose value carries a scheme, path, port or whitespace (`https://dc.example/`, `dc.example/api`, `dc.example:8443`): the discoverer must normalise host-only values, keep an explicit path, and reject anything with a scheme other than none/https. Test in Task 5.
- A template whose record host ends with a dot (`"host": "mail.example.net."`): absolute, not combined with the zone. Test in Task 7.
- A variable value containing `&`, `=`, `+`, space or non-ASCII in the apply URL: must survive encoding and the signature must be over the encoded form. Test in Task 6.
- A DNS host whose `urlSyncUX` already ends with `/` or carries a path (`https://dc.example/v2` is wrong, but `https://dc.example/connect` happens): the builder joins with exactly one `/` and never doubles `/v2`. Test in Task 6.
- A live TXT answer with the DKIM value split across multiple 255-byte strings: the check must compare the joined value, not the first chunk. Test in Task 8.

---

### Task 1: Template value objects

**Files:**
- Create: `src/DomainConnect/Enums/TemplateRecordType.php`, `src/DomainConnect/Enums/TxtConflictMatchingMode.php`, `src/DomainConnect/Enums/Essential.php`
- Create: `src/DomainConnect/TemplateRecord.php`, `src/DomainConnect/Template.php`
- Create: `src/DomainConnect/Exceptions/InvalidTemplate.php` (extends `Cbox\Dns\Exceptions\DnsException`)
- Test: `tests/Unit/DomainConnect/TemplateTest.php`
- Fixture: `tests/Fixtures/domain-connect/cbox.dk.engage-sending.json` (the template from the spec, verbatim)

**Interfaces:**
- Produces:
  - `enum TemplateRecordType: string { A, AAAA, CNAME, NS, TXT, MX, SRV, SPFM, APEXCNAME }` (values are the upper-case names)
  - `enum TxtConflictMatchingMode: string { None = 'None', All = 'All', Prefix = 'Prefix' }`
  - `enum Essential: string { Always = 'Always', OnApply = 'OnApply' }`
  - `readonly class TemplateRecord { __construct(public TemplateRecordType $type, public string $host, public ?string $pointsTo = null, public ?string $data = null, public ?string $spfRules = null, public ?int $ttl = null, public ?int $priority = null, public ?string $groupId = null, public Essential $essential = Essential::Always, public TxtConflictMatchingMode $txtConflictMatchingMode = TxtConflictMatchingMode::None, public ?string $txtConflictMatchingPrefix = null); static fromArray(array<string, mixed>): self; toArray(): array<string, mixed>; variables(): list<string> }`
  - `readonly class Template { __construct(public string $providerId, public string $providerName, public string $serviceId, public string $serviceName, public int $version, public array $records /* list<TemplateRecord> */, public ?string $syncPubKeyDomain = null, public ?string $syncRedirectDomain = null, public bool $syncBlock = false, public ?string $logoUrl = null, public ?string $description = null, public ?string $variableDescription = null); static fromJson(string): self; static fromArray(array<string, mixed>): self; toArray(): array<string, mixed>; variables(): list<string>; groupIds(): list<string> }`

- [ ] **Step 1: Write the failing tests**

```php
it('round-trips the engage-sending template through fromJson and toArray', function (): void {
    $json = file_get_contents(__DIR__.'/../../Fixtures/domain-connect/cbox.dk.engage-sending.json');
    $template = Template::fromJson($json);

    expect($template->providerId)->toBe('cbox.dk')
        ->and($template->serviceId)->toBe('engage-sending')
        ->and($template->syncPubKeyDomain)->toBe('cbox.dk')
        ->and($template->syncRedirectDomain)->toBe('cboxengage.com')
        ->and($template->records)->toHaveCount(4)
        ->and($template->records[1]->type)->toBe(TemplateRecordType::SPFM)
        ->and($template->records[3]->essential)->toBe(Essential::OnApply)
        ->and($template->records[3]->txtConflictMatchingMode)->toBe(TxtConflictMatchingMode::Prefix)
        ->and($template->toArray())->toBe(json_decode($json, true));
});

it('lists the variables and group ids a template uses, in order of first appearance', function (): void {
    expect($template->variables())->toBe(['mx', 'dkim'])
        ->and($template->groupIds())->toBe(['sending', 'dmarc']);
});

it('refuses a template without the required fields or with an unknown record type', function (): void {
    expect(fn () => Template::fromArray(['providerId' => 'x']))->toThrow(InvalidTemplate::class);
    expect(fn () => TemplateRecord::fromArray(['type' => 'PTR', 'host' => '@']))->toThrow(InvalidTemplate::class);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `vendor/bin/pest tests/Unit/DomainConnect/TemplateTest.php`
Expected: FAIL, class `Template` not found.

- [ ] **Step 3: Implement the enums, `TemplateRecord`, `Template`, `InvalidTemplate`**

`toArray()` emits only keys that are set (null and defaults omitted) so the round-trip equals the source JSON; the key order must follow the JSON schema's field order used in the fixture (`type`, `host`, `pointsTo`/`data`/`spfRules`, `priority`, `ttl`, `txtConflictMatchingMode`, `txtConflictMatchingPrefix`, `essential`, with `groupId` first when present). `variables()` scans `pointsTo`, `data`, `spfRules` with `/%([a-z0-9_]+)%/i`, de-duplicated, first-seen order.

- [ ] **Step 4: Run tests to verify they pass**

Run: `vendor/bin/pest tests/Unit/DomainConnect/TemplateTest.php`
Expected: PASS

- [ ] **Step 5: Gate and commit**

Run: `composer qa` — Expected: all green.

```bash
git add src/DomainConnect tests/Unit/DomainConnect tests/Fixtures/domain-connect
git commit -m "feat(domain-connect): template value objects"
```

---

### Task 2: Zone, ProviderSettings, Discovery, ApplyOutcome

**Files:**
- Create: `src/DomainConnect/Zone.php`, `src/DomainConnect/ProviderSettings.php`, `src/DomainConnect/Discovery.php`, `src/DomainConnect/ApplyOutcome.php`
- Test: `tests/Unit/DomainConnect/ValueObjectsTest.php`

**Interfaces:**
- Produces:
  - `readonly class Zone { __construct(public string $apex, public string $host = ''); fqdn(): string /* host.apex or apex */; isApex(): bool; static of(string $apex, string $host = ''): self /* lower-cases, trims dots */ }`
  - `readonly class ProviderSettings { __construct(public string $providerId, public string $providerName, public ?string $urlSyncUX = null, public ?string $urlAsyncUX = null, public ?string $urlAPI = null, public ?string $urlControlPanel = null, public int $width = 750, public int $height = 750, public array $nameServers = [] /* list<string> */); static fromArray(array<string, mixed>): self; toArray(): array<string, mixed>; supportsSync(): bool /* urlSyncUX !== null */ }`
  - `readonly class Discovery { __construct(public Zone $zone, public ?ProviderSettings $settings, public ?bool $supported, public DateTimeImmutable $checkedAt); isAvailable(): bool /* settings?->supportsSync() */; supportsTemplate(): bool /* supported === true */; toArray(): array<string, mixed>; static fromArray(array<string, mixed>): self }`
  - `readonly class ApplyOutcome { __construct(public ?string $state = null, public ?string $error = null, public ?string $errorDescription = null); succeeded(): bool; static fromQuery(array<string, mixed> $query): self }`

- [ ] **Step 1: Write the failing tests**

```php
it('splits a name into apex and host', function (): void {
    expect(Zone::of('Example.COM.', 'Mail')->fqdn())->toBe('mail.example.com')
        ->and(Zone::of('example.com')->isApex())->toBeTrue()
        ->and(Zone::of('example.com')->fqdn())->toBe('example.com');
});

it('reads provider settings with defaults and round-trips them', function (): void {
    $settings = ProviderSettings::fromArray(['providerId' => 'cloudflare.com', 'providerName' => 'Cloudflare', 'urlSyncUX' => 'https://domainconnect.cloudflare.com', 'urlAPI' => 'https://api.cloudflare.com/client/v4/domainconnect']);
    expect($settings->width)->toBe(750)->and($settings->supportsSync())->toBeTrue()
        ->and(ProviderSettings::fromArray($settings->toArray()))->toEqual($settings);
});

it('round-trips a discovery result, including the not-available case', function (): void {
    $none = new Discovery(Zone::of('example.com'), null, null, new DateTimeImmutable('2026-11-02T10:00:00Z'));
    expect($none->isAvailable())->toBeFalse()->and($none->supportsTemplate())->toBeFalse()
        ->and(Discovery::fromArray($none->toArray()))->toEqual($none);
});

it('parses the redirect back: success has no error; access_denied is a failure', function (): void {
    expect(ApplyOutcome::fromQuery(['state' => 'abc'])->succeeded())->toBeTrue()
        ->and(ApplyOutcome::fromQuery(['state' => 'abc', 'error' => 'access_denied', 'error_description' => 'User cancelled']))
            ->toEqual(new ApplyOutcome('abc', 'access_denied', 'User cancelled'));
});
```

- [ ] **Step 2: Run tests to verify they fail** — `vendor/bin/pest tests/Unit/DomainConnect/ValueObjectsTest.php`, expected FAIL (classes missing).

- [ ] **Step 3: Implement the four value objects**

`Discovery::toArray()` stores `checkedAt` as ISO-8601 (`DATE_ATOM`); `fromArray` accepts missing `settings` as null. `ApplyOutcome::fromQuery` reads only string values; anything else is null.

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect
git commit -m "feat(domain-connect): zone, provider settings, discovery and outcome value objects"
```

---

### Task 3: Transport contract, stream default and fake

**Files:**
- Create: `src/DomainConnect/Contracts/Transport.php`, `src/DomainConnect/HttpResponse.php`, `src/DomainConnect/Transports/StreamTransport.php`, `src/DomainConnect/Testing/FakeTransport.php`
- Test: `tests/Unit/DomainConnect/FakeTransportTest.php`, `tests/Unit/DomainConnect/StreamTransportTest.php`

**Interfaces:**
- Produces:
  - `interface Transport { get(string $url): HttpResponse; }`
  - `readonly class HttpResponse { __construct(public int $status, public string $body); ok(): bool /* 200–299 */; json(): ?array<string, mixed> }`
  - `class StreamTransport implements Transport { __construct(float $timeout = 5.0, ?callable $fetcher = null /* callable(string $url): HttpResponse, tests only */) }` — default uses `file_get_contents` with `ignore_errors => true`, parses the status from `$http_response_header`, no redirects followed (`follow_location => 0`), a transport failure is `HttpResponse(0, '')`.
  - `class FakeTransport implements Transport { stub(string $url, int $status, string|array $body): self; strict(bool $strict = true): self /* unstubbed URL throws LogicException */; requests(): list<string>; assertRequested(string $url): void }` — unstubbed and not strict → `HttpResponse(0, '')`.

- [ ] **Step 1: Write the failing tests**

```php
it('serves stubbed responses, records requests, and refuses unknown urls when strict', function (): void {
    $fake = (new FakeTransport)->stub('https://dc.example/v2/example.com/settings', 200, ['providerId' => 'x', 'providerName' => 'X']);
    expect($fake->get('https://dc.example/v2/example.com/settings')->json())->toBe(['providerId' => 'x', 'providerName' => 'X'])
        ->and($fake->get('https://other/')->status)->toBe(0)
        ->and($fake->requests())->toBe(['https://dc.example/v2/example.com/settings', 'https://other/']);
    expect(fn () => $fake->strict()->get('https://nope/'))->toThrow(LogicException::class);
});

it('turns a non-2xx status into ok() false and a non-JSON body into json() null', function (): void {
    expect((new HttpResponse(404, 'not found'))->ok())->toBeFalse()
        ->and((new HttpResponse(200, 'not json'))->json())->toBeNull();
});

it('does not follow redirects and reports transport failure as status 0', function (): void {
    $transport = new StreamTransport(fetcher: fn (string $url): HttpResponse => new HttpResponse(0, ''));
    expect($transport->get('https://unreachable.invalid/')->status)->toBe(0);
});
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `Transport`, `HttpResponse`, `StreamTransport`, `FakeTransport`**

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect
git commit -m "feat(domain-connect): transport contract with stream default and fake"
```

---

### Task 4: ZoneLocator

**Files:**
- Create: `src/DomainConnect/ZoneLocator.php`, `src/DomainConnect/Exceptions/ZoneNotFound.php` (extends `DnsException`)
- Test: `tests/Unit/DomainConnect/ZoneLocatorTest.php`

**Interfaces:**
- Consumes: `Cbox\Dns\Contracts\Resolver`, `Cbox\Dns\Testing\FakeResolver::stub()`, `RecordType::SOA`, `Zone` (Task 2).
- Produces: `class ZoneLocator { __construct(private readonly Resolver $resolver); locate(string $name): Zone }` — queries SOA for the name and each parent in turn; the first candidate whose SOA answer contains a record named exactly that candidate is the apex; stops before the public suffix is reached only by running out of labels (a TLD answering SOA is accepted, since some do); no hit → `ZoneNotFound`.

- [ ] **Step 1: Write the failing tests**

```php
it('finds the apex below a subdomain and returns the host part', function (): void {
    $fake = (new FakeResolver)
        ->stub('mail.acme.example', RecordType::SOA, [])
        ->stubRecords('acme.example', RecordType::SOA, [new DnsRecord(RecordType::SOA, 'acme.example', 'ns1.acme.example. hostmaster.acme.example. 1 7200 3600 1209600 300')]);
    expect((new ZoneLocator($fake))->locate('Mail.Acme.Example.'))->toEqual(Zone::of('acme.example', 'mail'));
});

it('returns the apex with an empty host when the name is the zone', function (): void { /* same stubs, locate('acme.example') → host '' */ });

it('throws ZoneNotFound when no SOA answers up the tree', function (): void {
    expect(fn () => (new ZoneLocator(new FakeResolver))->locate('nothing.invalid'))->toThrow(ZoneNotFound::class);
});

it('ignores a SOA that belongs to a parent (the authority section case)', function (): void {
    // A recursive answer for mail.acme.example may carry acme.example's SOA; that is not mail.acme.example's apex.
    $fake = (new FakeResolver)->stubRecords('mail.acme.example', RecordType::SOA, [new DnsRecord(RecordType::SOA, 'acme.example', '...')])
        ->stubRecords('acme.example', RecordType::SOA, [new DnsRecord(RecordType::SOA, 'acme.example', '...')]);
    expect((new ZoneLocator($fake))->locate('mail.acme.example')->apex)->toBe('acme.example');
});
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `ZoneLocator::locate()`**

Catch `DnsException` per query and treat it as "no SOA here"; lower-case and trim dots before walking.

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect
git commit -m "feat(domain-connect): locate a name's zone apex by SOA walk"
```

---

### Task 5: Discoverer

**Files:**
- Create: `src/DomainConnect/Discoverer.php`, `src/DomainConnect/Exceptions/DiscoveryRefused.php` (extends `DnsException`)
- Test: `tests/Unit/DomainConnect/DiscovererTest.php`

**Interfaces:**
- Consumes: `ZoneLocator` (Task 4), `Transport`/`FakeTransport` (Task 3), `Template` (Task 1), `ProviderSettings`/`Discovery` (Task 2), `Cbox\Dns\Support\IpAddress::isPublic()`, `Cbox\Dns\Dnssec\Contracts\Clock` (existing; `FrozenClock` in `Dnssec\Testing`).
- Produces: `class Discoverer { __construct(private readonly Resolver $resolver, private readonly Transport $transport, private readonly ZoneLocator $zones, private readonly Clock $clock = new SystemClock, private readonly bool $allowNonPublicHosts = false); discover(string $name, ?Template $template = null): Discovery }`
  - TXT `_domainconnect.<apex>` → first value, trimmed. Accept `host`, `host:port`, `host/path`; reject (→ `DiscoveryRefused`) a value with a scheme other than `https://`, with whitespace, or whose host resolves to any non-public address (A then AAAA via `$resolver`) unless `allowNonPublicHosts`. `http://` is refused.
  - Settings URL: `https://<value without trailing slash>/v2/<apex>/settings`. Non-2xx or non-JSON → `settings = null`.
  - With a template and `urlAPI` present: `GET <urlAPI>/v2/domainTemplates/providers/<providerId>/services/<serviceId>`; 2xx → `supported = true`, 404 → `false`, anything else → `null`.
  - No TXT, or TXT lookup throws → `Discovery` with `settings = null`, `supported = null`.

- [ ] **Step 1: Write the failing tests**

```php
it('discovers a provider and confirms template support', function (): void {
    $fake = zoneWithSoa('acme.example')->stub('_domainconnect.acme.example', RecordType::TXT, ['dc.cloudflare.example'])
        ->stub('dc.cloudflare.example', RecordType::A, ['203.0.113.10']);
    $http = (new FakeTransport)->strict()
        ->stub('https://dc.cloudflare.example/v2/acme.example/settings', 200, ['providerId' => 'cloudflare.com', 'providerName' => 'Cloudflare', 'urlSyncUX' => 'https://dc.cloudflare.example', 'urlAPI' => 'https://api.cloudflare.example'])
        ->stub('https://api.cloudflare.example/v2/domainTemplates/providers/cbox.dk/services/engage-sending', 200, '');
    $discovery = (new Discoverer($fake, $http, new ZoneLocator($fake), new FrozenClock(new DateTimeImmutable('2026-11-02T10:00:00Z'))))->discover('mail.acme.example', engageTemplate());

    expect($discovery->zone)->toEqual(Zone::of('acme.example', 'mail'))
        ->and($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($discovery->supported)->toBeTrue()
        ->and($discovery->checkedAt->format(DATE_ATOM))->toBe('2026-11-02T10:00:00+00:00');
});

it('reports supported=false on a 404 from the template check and null on a 500', function (): void { /* two cases via dataset */ });

it('yields no settings when there is no _domainconnect record', function (): void { /* settings null, supported null, no HTTP request made */ });

it('yields no settings when the settings call fails or is not JSON', function (string $status, string $body): void { })->with([['500', ''], ['200', 'not json']]);

it('normalises host-only, host:port and host/path values and rejects schemes other than https', function (string $txt, ?string $expectedUrl): void {
    // 'dc.example' → https://dc.example/v2/acme.example/settings
    // 'dc.example:8443' → https://dc.example:8443/v2/acme.example/settings
    // 'dc.example/connect/' → https://dc.example/connect/v2/acme.example/settings
    // 'https://dc.example' → https://dc.example/v2/acme.example/settings
    // 'http://dc.example' → DiscoveryRefused
    // 'dc.example /x' → DiscoveryRefused
})->with([...]);

it('refuses a discovery host that resolves to a private address unless allowed', function (): void {
    // A 10.0.0.5 → DiscoveryRefused; with allowNonPublicHosts: true → request is made
});
```

Add `zoneWithSoa(string $apex): FakeResolver` and `engageTemplate(): Template` helpers to `tests/Support/DomainConnectFixture.php` (final class with static methods, matching `DiagnosticFixture`); the template helper loads the Task 1 fixture.

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `Discoverer::discover()` and `DiscoveryRefused`**

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect tests/Support/DomainConnectFixture.php
git commit -m "feat(domain-connect): discover a zone's DNS provider and template support"
```

---

### Task 6: Signer, public-key records and the sync URL builder

**Files:**
- Create: `src/DomainConnect/Contracts/Signer.php`, `src/DomainConnect/Signers/OpenSslRs256Signer.php`, `src/DomainConnect/Testing/FakeSigner.php`, `src/DomainConnect/PublicKeyRecords.php`, `src/DomainConnect/ApplyRequest.php`, `src/DomainConnect/SyncUrlBuilder.php`, `src/DomainConnect/Exceptions/InvalidApplyRequest.php`, `src/DomainConnect/Exceptions/SyncFlowUnavailable.php` (both extend `DnsException`)
- Fixtures: `tests/Fixtures/domain-connect/test-private.pem`, `tests/Fixtures/domain-connect/test-public.pem`, `tests/Fixtures/domain-connect/reference-signature.txt`
- Test: `tests/Unit/DomainConnect/SignerTest.php`, `tests/Unit/DomainConnect/PublicKeyRecordsTest.php`, `tests/Unit/DomainConnect/SyncUrlBuilderTest.php`

**Interfaces:**
- Consumes: `Template`, `Zone`, `ProviderSettings`.
- Produces:
  - `interface Signer { sign(string $query): string /* standard base64, not URL-encoded */ }`
  - `class OpenSslRs256Signer implements Signer { __construct(string $privateKeyPem) }` — `RuntimeException` on missing ext-openssl or unreadable key; `openssl_sign($query, $sig, $key, OPENSSL_ALGO_SHA256)`.
  - `class FakeSigner implements Signer { sign(): 'ZmFrZS1zaWc=' ; signed(): list<string> /* queries seen */ }`
  - `class PublicKeyRecords { static for(string $publicKeyPem, int $chunk = 200): list<string>; static toPem(list<string> $records): string /* sort by p=, join d=, wrap as PEM */ }`
  - `readonly class ApplyRequest { __construct(public Template $template, public Zone $zone, public array $variables /* array<string,string> */, public array $groupIds = [] /* list<string> */, public ?string $redirectUri = null, public ?string $state = null) }`
  - `class SyncUrlBuilder { __construct(private readonly Signer $signer, private readonly string $keyHost = '_dcpubkeyv1'); build(ApplyRequest $request, ProviderSettings $settings): string }`
    - Base: `rtrim(urlSyncUX, '/') . '/v2/domainTemplates/providers/' . providerId . '/services/' . serviceId . '/apply'`; `SyncFlowUnavailable` when `urlSyncUX` is null or the template has `syncBlock`.
    - Query, in this order: `domain`, `host` (only when not apex), `redirect_uri`, `state` (each only when non-null), then every template variable in `Template::variables()` order, then `groupId` (comma-joined, only when non-empty). Encoded with `http_build_query($pairs, '', '&', PHP_QUERY_RFC3986)`.
    - `InvalidApplyRequest` when a template variable is missing from `$variables`, when `$variables` has a key the template does not use, or when a `groupId` is not in `Template::groupIds()`.
    - Then `&sig=` . rawurlencode(base64) . `&key=` . keyHost.

- [ ] **Step 1: Generate the test keypair and the reference signature (one-off, committed)**

```bash
openssl genrsa -out tests/Fixtures/domain-connect/test-private.pem 2048
openssl rsa -in tests/Fixtures/domain-connect/test-private.pem -pubout -out tests/Fixtures/domain-connect/test-public.pem
printf '%s' 'a=1&b=2&ip=10.10.10.10&domain=example.net' | openssl dgst -sha256 -sign tests/Fixtures/domain-connect/test-private.pem | base64 | tr -d '\n' > tests/Fixtures/domain-connect/reference-signature.txt
```

The `openssl dgst -sha256 -sign` output is RSA PKCS#1 v1.5 over SHA-256, the same construction the reference Python `domainconnect` library uses (`PKCS1_v1_5` + `SHA256` + `b64encode`). This is a test-only key; say so in a `README.md` next to it.

- [ ] **Step 2: Write the failing tests**

```php
it('signs the spec example exactly as the reference tooling does', function (): void {
    $signer = new OpenSslRs256Signer(file_get_contents(__DIR__.'/../../Fixtures/domain-connect/test-private.pem'));
    expect($signer->sign('a=1&b=2&ip=10.10.10.10&domain=example.net'))
        ->toBe(trim(file_get_contents(__DIR__.'/../../Fixtures/domain-connect/reference-signature.txt')));
});

it('produces a signature the published key verifies', function (): void {
    $records = PublicKeyRecords::for(file_get_contents(__DIR__.'/../../Fixtures/domain-connect/test-public.pem'));
    $pem = PublicKeyRecords::toPem($records);
    $sig = base64_decode((new OpenSslRs256Signer($privatePem))->sign('domain=example.net'));
    expect(openssl_verify('domain=example.net', $sig, openssl_pkey_get_public($pem), OPENSSL_ALGO_SHA256))->toBe(1);
});

it('splits the key into p=n,a=RS256,d=chunk strings no longer than 255 bytes and rebuilds it from any order', function (): void {
    $records = PublicKeyRecords::for($publicPem);
    expect($records[0])->toStartWith('p=1,a=RS256,d=')
        ->and(max(array_map('strlen', $records)))->toBeLessThanOrEqual(255)
        ->and(PublicKeyRecords::toPem(array_reverse($records)))->toBe(PublicKeyRecords::toPem($records));
});

it('builds the apply url with parameters in spec order, signed over the encoded query', function (): void {
    $signer = new FakeSigner;
    $url = (new SyncUrlBuilder($signer))->build(
        new ApplyRequest(engageTemplate(), Zone::of('acme.example', 'mail'), ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => 'MIGf+/=='], ['sending'], 'https://acme.cboxengage.com/settings/domains/connect/callback', 'st&ate'),
        new ProviderSettings('cloudflare.com', 'Cloudflare', urlSyncUX: 'https://dc.cloudflare.example/'),
    );
    $expectedQuery = 'domain=acme.example&host=mail&redirect_uri=https%3A%2F%2Facme.cboxengage.com%2Fsettings%2Fdomains%2Fconnect%2Fcallback&state=st%26ate&mx=feedback-smtp.eu-west-1.amazonses.com&dkim=MIGf%2B%2F%3D%3D&groupId=sending';
    expect($url)->toBe('https://dc.cloudflare.example/v2/domainTemplates/providers/cbox.dk/services/engage-sending/apply?'.$expectedQuery.'&sig=ZmFrZS1zaWc%3D&key=_dcpubkeyv1')
        ->and($signer->signed())->toBe([$expectedQuery]);
});

it('omits host for the apex and joins a urlSyncUX that carries a path with exactly one slash', function (): void {
    // urlSyncUX 'https://dc.example/connect' → '.../connect/v2/domainTemplates/...'; no 'host=' in the query
});

it('refuses a missing variable, an unknown variable, an unknown group, and a provider without sync', function (): void {
    // InvalidApplyRequest ×3, SyncFlowUnavailable ×1 (urlSyncUX null) — dataset
});
```

- [ ] **Step 3: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 4: Implement the signer, fake, `PublicKeyRecords`, `ApplyRequest`, `SyncUrlBuilder`, exceptions**

`PublicKeyRecords::for()`: strip PEM armour, remove newlines, `str_split` the base64 into `$chunk`-byte pieces, number from 1. `toPem()`: parse `p=` and `d=` from each string, sort by `p`, concatenate, wrap at 64 columns between `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----`.

- [ ] **Step 5: Run tests to verify they pass** — expected PASS.

- [ ] **Step 6: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect tests/Fixtures/domain-connect
git commit -m "feat(domain-connect): RS256 signer, public-key TXT records and the signed sync apply url"
```

---

### Task 7: RecordSet (template → expected records)

**Files:**
- Create: `src/DomainConnect/ExpectedRecord.php`, `src/DomainConnect/RecordSet.php`
- Test: `tests/Unit/DomainConnect/RecordSetTest.php`

**Interfaces:**
- Consumes: `Template`, `TemplateRecord`, `Zone`, `InvalidApplyRequest`.
- Produces:
  - `readonly class ExpectedRecord { __construct(public TemplateRecordType $type, public string $name /* fqdn, lower-case, no trailing dot */, public string $value, public ?int $priority = null, public ?int $ttl = null, public ?string $groupId = null) }` — for SPFM, `value` is the `spfRules` text.
  - `readonly class RecordSet { __construct(public Zone $zone, public array $records /* list<ExpectedRecord> */); static fromTemplate(Template $template, Zone $zone, array $variables, array $groupIds = []): self; toArray(): list<array<string, mixed>> }`
    - Host rule: `''`/`'@'` → `zone->fqdn()`; `x` → `x.<zone fqdn>`; trailing dot → absolute, dot stripped. Variables substituted in `pointsTo`/`data`/`spfRules` (missing → `InvalidApplyRequest`). Empty `$groupIds` → all records; otherwise only records whose `groupId` is in the list.

- [ ] **Step 1: Write the failing tests**

```php
it('expands the engage template for a subdomain with all groups', function (): void {
    $set = RecordSet::fromTemplate(engageTemplate(), Zone::of('acme.example', 'mail'), ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => 'MIGf']);
    expect($set->toArray())->toBe([
        ['type' => 'MX', 'name' => 'send.mail.acme.example', 'value' => 'feedback-smtp.eu-west-1.amazonses.com', 'priority' => 10, 'ttl' => 3600, 'groupId' => 'sending'],
        ['type' => 'SPFM', 'name' => 'send.mail.acme.example', 'value' => 'include:amazonses.com', 'priority' => null, 'ttl' => null, 'groupId' => 'sending'],
        ['type' => 'TXT', 'name' => 'resend._domainkey.mail.acme.example', 'value' => 'p=MIGf', 'priority' => null, 'ttl' => 3600, 'groupId' => 'sending'],
        ['type' => 'TXT', 'name' => '_dmarc.mail.acme.example', 'value' => 'v=DMARC1; p=quarantine', 'priority' => null, 'ttl' => 3600, 'groupId' => 'dmarc'],
    ]);
});

it('keeps only the requested groups', function (): void { /* ['sending'] → 3 records, none with groupId dmarc */ });

it('treats @ as the zone and a trailing dot as absolute', function (): void {
    $template = Template::fromArray([... records: [['type' => 'A', 'host' => '@', 'pointsTo' => '192.0.2.1', 'ttl' => 300], ['type' => 'CNAME', 'host' => 'www', 'pointsTo' => 'edge.cbox.example.', 'ttl' => 300], ['type' => 'TXT', 'host' => 'mail.example.net.', 'data' => 'x', 'ttl' => 300]]]);
    $names = array_map(fn (ExpectedRecord $r) => $r->name, RecordSet::fromTemplate($template, Zone::of('acme.example'), [])->records);
    expect($names)->toBe(['acme.example', 'www.acme.example', 'mail.example.net'])
        ->and(RecordSet::fromTemplate($template, Zone::of('acme.example'), [])->records[1]->value)->toBe('edge.cbox.example');
});

it('refuses a missing variable', function (): void { /* InvalidApplyRequest */ });
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `ExpectedRecord` and `RecordSet`**

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect
git commit -m "feat(domain-connect): expand a template into the records a zone should carry"
```

---

### Task 8: RecordSetCheck (expected vs live, through Diagnostics)

**Files:**
- Create: `src/DomainConnect/RecordSetCheck.php`
- Test: `tests/Unit/DomainConnect/RecordSetCheckTest.php`

**Interfaces:**
- Consumes: `Cbox\Dns\Diagnostics\Contracts\Check`, `DiagnosticContext` (`$ctx->authoritative->query($host, RecordType, $zone)`), `Finding::info/error`, `tests/Support/DiagnosticFixture::context()`, `RecordSet`.
- Produces: `class RecordSetCheck implements Check { __construct(private readonly RecordSet $set); run(DiagnosticContext $ctx): list<Finding> }` — category `'DomainConnect'`; check keys `domain-connect.present`, `domain-connect.missing`, `domain-connect.mismatch`; context carries `name`, `type`, `expected`, `live` (list of live values). Comparison rules: TXT exact after trim and joining multi-string answers; MX by lower-cased target without trailing dot and equal priority; A/AAAA/CNAME/NS lower-cased without trailing dot; SPFM: the TXT at `name` that starts with `v=spf1` contains the `spfRules` token (whitespace-delimited); APEXCNAME is checked as CNAME at the zone; SRV is reported as `info` with message "not checked" (no template of ours uses it). Resolution failure for a name → `missing` with `live = []`.

- [ ] **Step 1: Write the failing tests**

```php
it('reports every record present when the zone carries them, joining split TXT strings', function (): void {
    $fake = withAuthoritativeZone('acme.example', '192.0.2.1')
        ->stubRecords('send.acme.example', RecordType::MX, [new DnsRecord(RecordType::MX, 'send.acme.example', 'feedback-smtp.eu-west-1.amazonses.com.', priority: 10)], nameserver: '192.0.2.1')
        ->stub('send.acme.example', RecordType::TXT, ['v=spf1 include:amazonses.com ~all'], nameserver: '192.0.2.1')
        ->stub('resend._domainkey.acme.example', RecordType::TXT, ['p=MIGf'.str_repeat('A', 240).'B'.str_repeat('C', 50)], nameserver: '192.0.2.1')
        ->stub('_dmarc.acme.example', RecordType::TXT, ['v=DMARC1; p=quarantine'], nameserver: '192.0.2.1');
    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);
    expect($report->passed())->toBeTrue()->and($report->findings)->toHaveCount(4)
        ->and($report->findings[0]->check)->toBe('domain-connect.present');
});

it('reports missing and mismatched records with the live values in context', function (): void {
    // MX points elsewhere → mismatch with live ['other.example']; _dmarc absent → missing with live []
});

it('accepts an SPF record that contains the rule among others', function (): void { /* 'v=spf1 a include:_spf.google.com include:amazonses.com ~all' → present */ });
```

`withAuthoritativeZone()` goes in `DomainConnectFixture` (NS + A stubs like `DomainVerifierTest::withZone()`).

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `RecordSetCheck`**

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src/DomainConnect tests/Unit/DomainConnect tests/Support/DomainConnectFixture.php
git commit -m "feat(domain-connect): check a template's records against authoritative DNS"
```

---

### Task 9: The `DomainConnect` front door and `Dns::domainConnect()`

**Files:**
- Create: `src/DomainConnect/DomainConnect.php`, `src/DomainConnect/Testing/InteractsWithDomainConnect.php`
- Modify: `src/Dns.php` (add `domainConnect()`)
- Test: `tests/Unit/DomainConnect/DomainConnectTest.php`, `tests/Fixtures/InteractsWithDomainConnectFixture.php` (so PHPStan sees the trait composed)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `class DomainConnect { __construct(private readonly Discoverer $discoverer, private readonly SyncUrlBuilder $urls, private readonly Resolver $resolver); discover(string $name, ?Template $template = null): Discovery; applyUrl(ApplyRequest $request, ProviderSettings $settings): string; recordSet(Template $template, Zone $zone, array $variables, array $groupIds = []): RecordSet; check(RecordSet $set): Report /* Diagnostics($resolver)->runWith($set->zone->apex, [new RecordSetCheck($set)]) */; outcome(array $query): ApplyOutcome }`
  - `Dns::domainConnect(Signer $signer, ?Transport $transport = null, string $keyHost = '_dcpubkeyv1'): DomainConnect` — composes `ZoneLocator`, `Discoverer` (with this facade's resolver and `allowNonPublicNameservers` passed as `allowNonPublicHosts`), `SyncUrlBuilder`.
  - `trait InteractsWithDomainConnect { uses InteractsWithDns; fakeTransport(): FakeTransport; fakeSigner(): FakeSigner; domainConnect(): DomainConnect /* built over fakeDns(), fakeTransport(), fakeSigner() */ }`

- [ ] **Step 1: Write the failing tests**

```php
it('composes discovery, url building and checking over one resolver and transport', function (): void {
    // via the trait: stub zone + _domainconnect + settings + support; discover → applyUrl → check (records absent → report has errors)
    $dc = $this->domainConnect(); // test uses the fixture class or a pest `uses()` of the trait
    $discovery = $dc->discover('acme.example', engageTemplate());
    expect($discovery->supportsTemplate())->toBeTrue();
    $url = $dc->applyUrl(new ApplyRequest(engageTemplate(), $discovery->zone, ['mx' => 'm', 'dkim' => 'k']), $discovery->settings);
    expect($url)->toContain('/providers/cbox.dk/services/engage-sending/apply?domain=acme.example&');
    expect($dc->check($dc->recordSet(engageTemplate(), $discovery->zone, ['mx' => 'm', 'dkim' => 'k']))->hasErrors())->toBeTrue();
});

it('is reachable from the Dns facade', function (): void {
    expect((new Dns(new FakeResolver))->domainConnect(new FakeSigner, new FakeTransport))->toBeInstanceOf(DomainConnect::class);
});
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement `DomainConnect`, the trait, the fixture class, and `Dns::domainConnect()`**

`Dns` currently hands `allowNonPublicNameservers` straight to `AuthoritativeResolver`; keep it as a `private readonly bool` as well so `domainConnect()` can pass it on.

- [ ] **Step 4: Run tests to verify they pass** — expected PASS.

- [ ] **Step 5: Gate and commit**

```bash
composer qa
git add src tests
git commit -m "feat(domain-connect): front door, Dns::domainConnect() and the testing trait"
```

---

### Task 10: Docs, changelog, requirements

**Files:**
- Create: `docs/domain-connect/_index.md`, `docs/domain-connect/discovery.md`, `docs/domain-connect/signing.md`, `docs/domain-connect/templates.md`, `docs/domain-connect/testing.md`
- Modify: `docs/index.md` (add the section to the TOC), `docs/security/_index.md` (SSRF note for discovery hosts; what we do and do not sign), `CHANGELOG.md` (`## [Unreleased]` → `### Added`), `composer.json` (`suggest` gains `ext-openssl` wording for Domain Connect signing; keywords add `domain-connect`), `README.md` (one short section with the three-call example).

- [ ] **Step 1: Write the five docs pages**

Frontmatter `title`/`weight`/`description` on each; `_index.md` weight below the files. `signing.md` shows the `_dcpubkeyv1` TXT format and the rotation story (publish v2, switch `keyHost`, remove v1). `templates.md` shows the host rule, variables, groups, and says the template lives in the public Templates repository (no competitor names). `testing.md` shows `InteractsWithDomainConnect`.

- [ ] **Step 2: Update `docs/index.md`, `docs/security/_index.md`, `CHANGELOG.md`, `composer.json`, `README.md`**

- [ ] **Step 3: Verify no dangling links**

Run: `grep -rno "](\.\./[^)]*\|]([a-z-]*/[^)]*\|]([a-z-]*\.md)" docs | sed 's/.*](//' | sort -u` and check each target exists.
Expected: every path resolves.

- [ ] **Step 4: Gate and commit**

```bash
composer qa
git add docs CHANGELOG.md composer.json README.md
git commit -m "docs(domain-connect): discovery, signing, templates and testing"
```

Release (tag, Packagist) is a separate step under the `cbox-release` skill, not part of this plan.
