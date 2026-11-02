<?php

declare(strict_types=1);

use Cbox\Dns\Dns;
use Cbox\Dns\DomainConnect\ApplyRequest;
use Cbox\Dns\DomainConnect\DomainConnect;
use Cbox\Dns\DomainConnect\Exceptions\DiscoveryRefused;
use Cbox\Dns\DomainConnect\ProviderSettings;
use Cbox\Dns\DomainConnect\Testing\FakeSigner;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\Testing\InteractsWithDomainConnect;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

uses(InteractsWithDomainConnect::class);

it('composes discovery, url building and checking over one resolver and transport', function (): void {
    $template = DomainConnectFixture::engageTemplate();
    $variables = DomainConnectFixture::engageVariables();
    $this->stubZone('acme.example', ['ns1.acme.example' => DomainConnectFixture::NS_IP]);
    DomainConnectFixture::stubDiscoveryOn($this->fakeDns());
    $this->fakeTransport()
        ->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS)
        ->stub(DomainConnectFixture::SUPPORT_URL, 200, '');

    $dc = $this->domainConnect();
    $discovery = $dc->discover('acme.example', $template);

    expect($discovery->supportsTemplate())->toBeTrue();

    $url = $dc->applyUrl(new ApplyRequest($template, $discovery->zone, $variables), $discovery->settings);

    expect($url)->toContain('/providers/cbox.dk/services/engage-sending/apply?domain=acme.example&')
        ->and($dc->check($dc->recordSet($template, $discovery->zone, $variables))->hasErrors())->toBeTrue();
});

it('is reachable from the Dns facade', function (): void {
    expect((new Dns(new FakeResolver))->domainConnect(new FakeSigner, new FakeTransport))->toBeInstanceOf(DomainConnect::class);
});

it('keeps the discovery host check on even when the facade allows non-public nameservers', function (): void {
    $fake = DomainConnectFixture::discoveryResolver(address: '10.0.0.5');
    $http = (new FakeTransport)->strict()->stub(DomainConnectFixture::SETTINGS_URL, 200, DomainConnectFixture::SETTINGS);

    expect(fn () => (new Dns($fake, allowNonPublicNameservers: true))->domainConnect(new FakeSigner, $http)->discover('acme.example'))
        ->toThrow(DiscoveryRefused::class);
    expect($http->requests())->toBe([]);

    $discovery = (new Dns($fake))->domainConnect(new FakeSigner, $http, allowNonPublicHosts: true)->discover('acme.example');

    expect($discovery->settings?->providerName)->toBe('Cloudflare')
        ->and($http->requests())->toBe([DomainConnectFixture::SETTINGS_URL]);
});

it('passes the key host to the apply URL', function (): void {
    $dc = (new Dns(new FakeResolver))->domainConnect(new FakeSigner, new FakeTransport, '_dcpubkeyv2');
    $url = $dc->applyUrl(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), DomainConnectFixture::engageVariables()),
        new ProviderSettings('cloudflare.com', 'Cloudflare', urlSyncUX: 'https://dc.cloudflare.example'),
    );

    expect($url)->toEndWith('&key=_dcpubkeyv2');
});
