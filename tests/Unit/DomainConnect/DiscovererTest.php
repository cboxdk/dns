<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Exceptions\DiscoveryRefused;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DomainConnectFixture;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

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
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL, DomainConnectFixture::SUPPORT_URL])
        ->and($http->pinned())->toBe([
            DomainConnectFixture::SETTINGS_URL => '203.0.113.10',
            DomainConnectFixture::SUPPORT_URL => DomainConnectFixture::API_ADDRESS,
        ]);
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

it('skips the template check without a template, without urlAPI, or with a non-https urlAPI', function (bool $withTemplate, ?string $urlApi): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, ['urlAPI' => $urlApi]));

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)
        ->discover('acme.example', $withTemplate ? DomainConnectFixture::engageTemplate() : null);

    expect($discovery->settings?->providerId)->toBe('cloudflare.com')
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
})->with([
    'no template' => [false, 'https://api.cloudflare.example'],
    'no urlAPI' => [true, null],
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
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stubFailure('_domainconnect.acme.example', RecordType::TXT, Rcode::ServFail);
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([]);
});

it('yields no settings when the TXT lookup throws', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')->strict();
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($discovery->settings)->toBeNull()
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
    'userinfo with password' => ['example.com:x@127.0.0.1'],
    'userinfo with port-like password' => ['example.com:443@169.254.169.254'],
    'userinfo before an IPv6 literal' => ['example.com:@[::1]'],
    'plain userinfo' => ['user@dc.example'],
    'fragment' => ['a.attacker.com#.attacker.com'],
    'query' => ['dc.example?x=.attacker.com'],
    'host outside the hostname charset' => ['dc_example'],
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

    $http = (new FakeTransport)->strict();

    expect(fn () => DomainConnectFixture::discoverer($fake, $http)->discover('acme.example'))
        ->toThrow(DiscoveryRefused::class);
    expect($http->requests())->toBe([]);
});

it('pins a public IP literal host to itself', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['[2001:4860::1]:8443']);
    $url = 'https://[2001:4860::1]:8443/v2/acme.example/settings';
    $http = (new FakeTransport)->strict()->stub($url, 200, DomainConnectFixture::SETTINGS);

    DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($http->pinned())->toBe([$url => '2001:4860::1']);
});

it('pins the AAAA address when the host has no A record', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['dc.cloudflare.example'])
        ->stub('dc.cloudflare.example', RecordType::AAAA, ['2001:4860::10']);
    $http = (new FakeTransport)->strict()->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS);

    DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($http->pinned())->toBe([DomainConnectFixture::SETTINGS_URL => '2001:4860::10']);
});

it('fails closed when either address lookup of the discovery host fails', function (RecordType $failing): void {
    $fake = DomainConnectFixture::discoveryResolver()
        ->stub('dc.cloudflare.example', RecordType::AAAA, ['2001:4860::10'])
        ->stubFailure('dc.cloudflare.example', $failing, Rcode::ServFail);
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([]);
})->with([
    'A' => [RecordType::A],
    'AAAA' => [RecordType::AAAA],
]);

it('fails closed when the A lookup of the discovery host throws', function (): void {
    $fake = new class extends FakeResolver
    {
        public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
        {
            if ($host === 'dc.cloudflare.example' && $type === RecordType::A) {
                throw ResolutionFailed::make('192.0.2.1', 'timed out');
            }

            return parent::query($host, $type, $nameserver, $recursion, $dnssec);
        }
    };
    $fake->stubRecords('acme.example', RecordType::SOA, [DomainConnectFixture::soa('acme.example')])
        ->stub('_domainconnect.acme.example', RecordType::TXT, ['dc.cloudflare.example'])
        ->stub('dc.cloudflare.example', RecordType::AAAA, ['2001:4860::10']);
    $http = (new FakeTransport)->strict();

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example');

    expect($discovery->settings)->toBeNull()
        ->and($http->requests())->toBe([]);
});

it('skips the template check when urlAPI is unsafe or its host does not resolve cleanly', function (string $urlApi, ?string $apiAddress, bool $apiLookupFails): void {
    $fake = DomainConnectFixture::discoveryResolver();

    if ($apiAddress !== null) {
        $fake->stub('api.internal.example', RecordType::A, [$apiAddress]);
    }

    if ($apiLookupFails) {
        $fake->stubFailure('api.internal.example', RecordType::A, Rcode::ServFail);
    }

    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, ['urlAPI' => $urlApi]));

    $discovery = DomainConnectFixture::discoverer($fake, $http)->discover('acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
})->with([
    'private address' => ['https://api.internal.example', '10.0.0.7', false],
    'no address' => ['https://api.internal.example', null, false],
    'lookup throws' => ['https://api.internal.example', null, true],
    'private IP literal' => ['https://169.254.169.254', null, false],
]);

it('yields no settings and makes no further request when a settings URL is not plain https', function (string $field, string $url): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, [$field => $url]));

    $discovery = DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)->discover('acme.example', DomainConnectFixture::engageTemplate());

    expect($discovery->settings)->toBeNull()
        ->and($discovery->supported)->toBeNull()
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
})->with([
    'javascript urlSyncUX' => ['urlSyncUX', 'javascript:alert(1)'],
    'http urlAPI' => ['urlAPI', 'http://api.cloudflare.example'],
    'urlAPI with userinfo' => ['urlAPI', 'https://api.cloudflare.example:x@127.0.0.1'],
    'urlAPI with a query' => ['urlAPI', 'https://api.cloudflare.example?x=1'],
    'urlAPI with a fragment' => ['urlAPI', 'https://api.cloudflare.example#x'],
]);

it('does not double /v2 when urlAPI already ends in it', function (string $urlApi): void {
    $http = (new FakeTransport)->strict()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, array_merge(DomainConnectFixture::SETTINGS, ['urlAPI' => $urlApi]))
        ->stub(DomainConnectFixture::SUPPORT_URL, 200, '');

    expect(DomainConnectFixture::discoverer(DomainConnectFixture::discoveryResolver(), $http)->discover('acme.example', DomainConnectFixture::engageTemplate())->supported)->toBeTrue();
})->with(['https://api.cloudflare.example/v2', 'https://api.cloudflare.example/V2/']);

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
