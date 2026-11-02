<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\ApplyRequest;
use Cbox\Dns\DomainConnect\Exceptions\InvalidApplyRequest;
use Cbox\Dns\DomainConnect\Exceptions\SyncFlowUnavailable;
use Cbox\Dns\DomainConnect\ProviderSettings;
use Cbox\Dns\DomainConnect\SyncUrlBuilder;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\Testing\FakeSigner;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

it('builds the apply url with parameters in spec order, signed over the encoded query', function (): void {
    $signer = new FakeSigner;
    $url = (new SyncUrlBuilder($signer))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example', 'mail'), ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => 'MIGf+/=='], ['sending'], 'https://acme.cboxengage.com/settings/domains/connect/callback', 'st&ate'),
        new ProviderSettings('cloudflare.com', 'Cloudflare', urlSyncUX: 'https://dc.cloudflare.example/'),
    );
    $expectedQuery = 'domain=acme.example&host=mail&redirect_uri=https%3A%2F%2Facme.cboxengage.com%2Fsettings%2Fdomains%2Fconnect%2Fcallback&state=st%26ate&mx=feedback-smtp.eu-west-1.amazonses.com&dkim=MIGf%2B%2F%3D%3D&groupId=sending';

    expect($url)->toBe('https://dc.cloudflare.example/v2/domainTemplates/providers/cbox.dk/services/engage-sending/apply?'.$expectedQuery.'&sig=ZmFrZS1zaWc%3D&key=_dcpubkeyv1')
        ->and($signer->signed())->toBe([$expectedQuery]);
});

it('omits host for the apex and joins a urlSyncUX that carries a path with exactly one slash', function (): void {
    $signer = new FakeSigner;
    $url = (new SyncUrlBuilder($signer, '_dck2'))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['dkim' => 'k', 'mx' => 'm']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example/connect'),
    );

    expect($url)->toBe('https://dc.example/connect/v2/domainTemplates/providers/cbox.dk/services/engage-sending/apply?domain=acme.example&mx=m&dkim=k&sig=ZmFrZS1zaWc%3D&key=_dck2')
        ->and($signer->signed())->toBe(['domain=acme.example&mx=m&dkim=k']);
});

it('joins a urlSyncUX that already ends in /v2 without doubling it', function (string $urlSyncUx, string $prefix): void {
    $url = (new SyncUrlBuilder(new FakeSigner))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['dkim' => 'k', 'mx' => 'm']),
        new ProviderSettings('example', 'Example', urlSyncUX: $urlSyncUx),
    );

    expect($url)->toStartWith($prefix.'/v2/domainTemplates/providers/cbox.dk/services/engage-sending/apply?');
})->with([
    'ends in /v2' => ['https://dc.example/v2', 'https://dc.example'],
    'ends in /v2/' => ['https://dc.example/v2/', 'https://dc.example'],
    'ends in /V2' => ['https://dc.example/V2', 'https://dc.example'],
    'carries a path' => ['https://dc.example/connect', 'https://dc.example/connect'],
    'path ends in v2 without a slash' => ['https://dc.example/connectv2', 'https://dc.example/connectv2'],
]);

it('percent-encodes a variable with a space and non-ASCII characters in the signed query', function (): void {
    $signer = new FakeSigner;
    $url = (new SyncUrlBuilder($signer))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k ø']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
    );

    expect($signer->signed())->toBe(['domain=acme.example&mx=m&dkim=k%20%C3%B8'])
        ->and($url)->toContain('?domain=acme.example&mx=m&dkim=k%20%C3%B8&sig=');
});

it('joins several groups with a comma', function (): void {
    $signer = new FakeSigner;
    (new SyncUrlBuilder($signer))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k'], ['sending', 'dmarc']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
    );

    expect($signer->signed())->toBe(['domain=acme.example&mx=m&dkim=k&groupId=sending%2Cdmarc']);
});

it('sends each group once', function (): void {
    $signer = new FakeSigner;
    (new SyncUrlBuilder($signer))->build(
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k'], ['sending', 'sending']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
    );

    expect($signer->signed())->toBe(['domain=acme.example&mx=m&dkim=k&groupId=sending']);
});

it('refuses a missing variable, an unknown variable, an unknown group, and a provider without sync', function (ApplyRequest $request, ProviderSettings $settings, string $exception): void {
    $signer = new FakeSigner;

    expect(fn () => (new SyncUrlBuilder($signer))->build($request, $settings))->toThrow($exception)
        ->and($signer->signed())->toBe([]);
})->with([
    'missing variable' => fn () => [
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        InvalidApplyRequest::class,
    ],
    'unknown variable' => fn () => [
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k', 'ip' => '1.2.3.4']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        InvalidApplyRequest::class,
    ],
    'unknown group' => fn () => [
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k'], ['web']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        InvalidApplyRequest::class,
    ],
    'provider without sync' => fn () => [
        new ApplyRequest(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k']),
        new ProviderSettings('example', 'Example'),
        SyncFlowUnavailable::class,
    ],
    'variable named like a built-in parameter' => fn () => [
        new ApplyRequest(DomainConnectFixture::templateWithRecords([['type' => 'TXT', 'host' => '@', 'data' => '%state%', 'ttl' => 3600]]), Zone::of('acme.example'), ['state' => 'x']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        InvalidApplyRequest::class,
    ],
    'variable named sig, in any case' => fn () => [
        new ApplyRequest(DomainConnectFixture::templateWithRecords([['type' => 'TXT', 'host' => '@', 'data' => '%SIG%', 'ttl' => 3600]]), Zone::of('acme.example'), ['SIG' => 'x']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        InvalidApplyRequest::class,
    ],
    'template blocks sync' => fn () => [
        new ApplyRequest(Template::fromArray([...DomainConnectFixture::engageTemplate()->toArray(), 'syncBlock' => true]), Zone::of('acme.example'), ['mx' => 'm', 'dkim' => 'k']),
        new ProviderSettings('example', 'Example', urlSyncUX: 'https://dc.example'),
        SyncFlowUnavailable::class,
    ],
]);
