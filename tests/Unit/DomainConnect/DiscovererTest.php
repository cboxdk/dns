<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Exceptions\DiscoveryRefused;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DomainConnectFixture;
use Cbox\Dns\ValueObjects\DnsRecord;

it('discovers a provider and confirms template support', function (): void {
    $fake = DomainConnectFixture::discoveryResolver();
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS)
        ->stub(DomainConnectFixture::SUPPORT_URL, 200, '');

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('mail.acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->zone)->toEqual(Zone::of('acme.example', 'mail'))
        ->and($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($discovery->supported)->toBeTrue()
        ->and($discovery->checkedAt->format(DATE_ATOM))->toBe('2026-11-02T10:00:00+00:00')
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL, DomainConnectFixture::SUPPORT_URL]);
});

it('reports the template check outcome from its status', function (int $status, ?bool $supported): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS)
        ->stub(DomainConnectFixture::SUPPORT_URL, $status, '');

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)->discover('acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->settings)->not->toBeNull()
        ->and($discovery->supported)->toBe($supported);
})->with([
    '404 is unsupported' => [404, false],
    '500 is unknown' => [500, null],
    'transport failure is unknown' => [0, null],
]);

it('skips the template check without a template, without urlAPI, or with a non-https urlAPI', function (?bool $withTemplate, ?string $urlApi): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, ['urlAPI' => $urlApi]));

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)
        ->discover('acme.example', $withTemplate === true ? DomainConnectFixture::engageTemplate() : null);

    expect($discovery->settings?->providerId)->toBe('cloudflare.com')
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
})->with([
    'no template' => [false, 'https://api.cloudflare.example'],
    'no urlAPI' => [true, null],
    'http urlAPI' => [true, 'http://api.cloudflare.example'],
]);

it('builds the support URL from urlAPI without a doubled slash', function (): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, ['urlAPI' => 'https://api.cloudflare.example/']))
        ->stub(DomainConnectFixture::SUPPORT_URL, 200, '');

    expect(DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)->discover('acme.example', DomainConnectFixture::engageTemplate())->supported)->toBeTrue();
});

it('yields no settings when there is no _domainconnect record', function (): void {
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::resolverWithZone('acme.example'), $http)
        ->discover('mail.acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->zone)->toEqual(Zone::of('acme.example', 'mail'))
        ->and($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($discovery->checkedAt->format(DATE_ATOM))->toBe('2026-11-02T10:00:00+00:00')
        ->and($http->requests())->toBe([]);
});

it('yields no settings when the TXT lookup fails', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')->strict()
        ->stubFailure('_domainconnect.acme.example', RecordType::TXT, Rcode::ServFail);
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([]);
});

it('yields no settings when the settings call fails or is not usable', function (int $status, string $body): void {
    $http = (new FakeTransport)->strict()->stub(DomainConnectFixture::SETTINGS_URL, $status, $body);

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)->discover('acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
})->with([
    'server error' => [500, ''],
    'not json' => [200, 'not json'],
    'malformed settings' => [200, '{"providerId":"cloudflare.com"}'],
    'transport failure' => [0, ''],
]);

it('normalises host-only, host:port, host/path and https values', function (string $txt, string $expectedUrl): void {
    $http = (new FakeTransport)->strict()->stub($expectedUrl, 200, DomainConnectFixture::SETTINGS);

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver($txt, host: 'dc.example'), $http)->discover('acme.example');

    expect($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($http->requests())->toBe([$expectedUrl]);
})->with([
    'host' => ['dc.example', 'https://dc.example/v2/acme.example/settings'],
    'host with trailing slash' => ['dc.example/', 'https://dc.example/v2/acme.example/settings'],
    'host:port' => ['dc.example:8443', 'https://dc.example:8443/v2/acme.example/settings'],
    'host/path' => ['dc.example/connect/', 'https://dc.example/connect/v2/acme.example/settings'],
    'https scheme' => ['https://dc.example', 'https://dc.example/v2/acme.example/settings'],
    'padded' => ['  dc.example  ', 'https://dc.example/v2/acme.example/settings'],
]);

it('refuses a value with a non-https scheme or whitespace', function (string $txt): void {
    $http = (new FakeTransport)->strict();

    expect(fn () => DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver($txt, host: 'dc.example'), $http)->discover('acme.example'))
        ->toThrow(DiscoveryRefused::class);
    expect($http->requests())->toBe([]);
})->with([
    'http' => ['http://dc.example'],
    'ftp' => ['ftp://dc.example'],
    'inner whitespace' => ['dc.example /x'],
]);

it('refuses a discovery host that resolves to a private address unless allowed', function (): void {
    $http = (new FakeTransport)->strict()->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS);

    expect(fn () => DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(address: '10.0.0.5'), $http)->discover('acme.example'))
        ->toThrow(DiscoveryRefused::class);
    expect($http->requests())->toBe([]);

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(address: '10.0.0.5'), $http, allowNonPublicHosts: true)->discover('acme.example');

    expect($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
});

it('refuses when any AAAA address of the host is non-public', function (): void {
    $fake = DomainConnectFixture::discoveryResolver()->stub('dc.cloudflare.example', RecordType::AAAA, ['::1']);
    $http = (new FakeTransport)->strict();

    expect(fn () => DomainConnectFixture::discoverer($fake, $http)->discover('acme.example'))->toThrow(DiscoveryRefused::class);
    expect($http->requests())->toBe([]);
});

it('refuses an IP literal host that is non-public', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['169.254.169.254']);

    expect(fn () => DomainConnectFixture::discoverer($fake, (new FakeTransport)->strict())->discover('acme.example'))
        ->toThrow(DiscoveryRefused::class);
});

it('yields no settings when the discovery host has no address', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['dc.cloudflare.example']);
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([]);
});

it('ignores CNAME records carried in the TXT and address answers', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stubRecords('_domainconnect.acme.example', RecordType::TXT, [
            new DnsRecord(RecordType::CNAME, '_domainconnect.acme.example', 'dc.cloudflare.example.'),
            new DnsRecord(RecordType::TXT, 'dc.cloudflare.example', 'dc.cloudflare.example'),
        ])
        ->stubRecords('dc.cloudflare.example', RecordType::A, [
            new DnsRecord(RecordType::CNAME, 'dc.cloudflare.example', 'edge.cloudflare.example.'),
            new DnsRecord(RecordType::A, 'edge.cloudflare.example', '203.0.113.10'),
        ]);
    $http = (new FakeTransport)->strict()->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS);

    expect(DomainConnectFixture::discoverer($fake, $http)->discover('acme.example')->settings?->providerName)->toBe('Cloudflare');
});
