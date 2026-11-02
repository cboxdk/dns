---
title: Testing
weight: 49
description: Drive Domain Connect offline with InteractsWithDomainConnect, FakeTransport and FakeSigner — no network, no private key.
---

# Testing Domain Connect

Everything the module does goes through three seams: the `Resolver` (DNS), the
`Transport` (HTTPS), and the `Signer`. Each has a fake, so a test needs no network
and no private key.

## `FakeTransport`

`Cbox\Dns\DomainConnect\Testing\FakeTransport` answers `GET` requests from stubs:

```php
use Cbox\Dns\DomainConnect\Testing\FakeTransport;

$http = (new FakeTransport)
    ->stub('https://dc.provider.example/v2/acme.example/settings', 200, [
        'providerId' => 'provider.example',
        'providerName' => 'Provider',
        'urlSyncUX' => 'https://connect.provider.example',
    ])                          // an array body is JSON-encoded
    ->strict();                 // an unstubbed URL throws instead of failing quietly

$http->requests();              // every URL requested, in order
$http->pinned();                // URL => the address it was pinned to (null: not pinned)
$http->assertRequested('https://dc.provider.example/v2/acme.example/settings');
```

Without `strict()`, an unstubbed URL gets a status-`0` response, which is how a
transport reports a failure.

## `FakeSigner`

`Cbox\Dns\DomainConnect\Testing\FakeSigner` returns a fixed signature,
`FakeSigner::SIGNATURE` (`ZmFrZS1zaWc=`), and records every query it signed in
`signed()`. Assert on the exact query string that would have been signed without
handling a key. The real signer is tested against a committed test-only keypair; see
[Signing](signing.md#test-keypair).

## `InteractsWithDomainConnect`

`Cbox\Dns\DomainConnect\Testing\InteractsWithDomainConnect` builds on
[`InteractsWithDns`](../getting-started/testing.md) (so `fakeDns()` and `stubZone()`
are there too) and adds:

- `fakeTransport()` — a shared `FakeTransport` for the test;
- `fakeSigner()` — a shared `FakeSigner`;
- `domainConnect(string $keyHost = '_dcpubkeyv1')` — a `DomainConnect` wired over the
  fake resolver, transport and signer.

The facade it builds on allows non-public nameserver addresses, so discovery runs
with `allowNonPublicHosts` on: no `A`/`AAAA` stubs are needed for the provider's
hosts, and requests are not pinned. To test the address check and the pinning,
build a `Discoverer` yourself with `allowNonPublicHosts: false`.

## End to end

```php
use Cbox\Dns\DomainConnect\ApplyRequest;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\Testing\InteractsWithDomainConnect;
use Cbox\Dns\Enums\RecordType;

uses(InteractsWithDomainConnect::class);

it('discovers, builds a signed apply URL and checks the records', function (): void {
    $template = Template::fromJson(<<<'JSON'
        {
          "providerId": "example.com",
          "providerName": "Example",
          "serviceId": "mail",
          "serviceName": "Example mail",
          "version": 1,
          "syncPubKeyDomain": "example.com",
          "records": [
            { "type": "TXT", "host": "_verify", "data": "token=%token%", "ttl": 3600 }
          ]
        }
        JSON);

    // The customer's zone: delegation, SOA, and the _domainconnect pointer.
    $this->stubZone('acme.example', ['ns1.acme.example' => '192.0.2.1'])
        ->stub('acme.example', RecordType::SOA, ['ns1.acme.example. hostmaster.acme.example. 1 7200 3600 1209600 300'])
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['dc.provider.example']);

    // The DNS provider's settings document and template-support answer.
    $this->fakeTransport()
        ->strict()
        ->stub('https://dc.provider.example/v2/acme.example/settings', 200, [
            'providerId' => 'provider.example',
            'providerName' => 'Provider',
            'urlSyncUX' => 'https://connect.provider.example',
            'urlAPI' => 'https://api.provider.example',
        ])
        ->stub('https://api.provider.example/v2/domainTemplates/providers/example.com/services/mail', 200, '');

    $dc = $this->domainConnect();
    $discovery = $dc->discover('acme.example', $template);

    expect($discovery->isAvailable())->toBeTrue()
        ->and($discovery->supportsTemplate())->toBeTrue();

    $url = $dc->applyUrl(
        new ApplyRequest($template, $discovery->zone, ['token' => 'abc123'], state: 'opaque-state'),
        $discovery->settings,
    );

    expect($url)->toBe('https://connect.provider.example/v2/domainTemplates/providers/example.com/services/mail/apply'
        .'?domain=acme.example&state=opaque-state&token=abc123&sig=ZmFrZS1zaWc%3D&key=_dcpubkeyv1')
        ->and($this->fakeSigner()->signed())->toBe(['domain=acme.example&state=opaque-state&token=abc123']);

    // After the customer applied the template, the record is live at the zone's nameserver.
    $this->fakeDns()->stub('_verify.acme.example', RecordType::TXT, ['token=abc123'], nameserver: '192.0.2.1');

    $report = $dc->check($dc->recordSet($template, $discovery->zone, ['token' => 'abc123']));

    expect($report->passed())->toBeTrue()
        ->and($report->findings[0]->check)->toBe('domain-connect.present')
        ->and($dc->outcome(['state' => 'opaque-state'])->succeeded())->toBeTrue()
        ->and($dc->outcome(['state' => 'opaque-state', 'error' => 'access_denied'])->succeeded())->toBeFalse();
});
```

The package's own `tests/Unit/DomainConnect/DomainConnectTest.php` follows the same
shape with the fixture template in `tests/Fixtures/domain-connect/`.
