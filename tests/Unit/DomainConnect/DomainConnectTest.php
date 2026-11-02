<?php

declare(strict_types=1);

use Cbox\Dns\Dns;
use Cbox\Dns\DomainConnect\ApplyRequest;
use Cbox\Dns\DomainConnect\DomainConnect;
use Cbox\Dns\DomainConnect\Testing\FakeSigner;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\Testing\InteractsWithDomainConnect;
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
