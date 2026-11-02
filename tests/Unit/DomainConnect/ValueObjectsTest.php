<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\ApplyOutcome;
use Cbox\Dns\DomainConnect\Discovery;
use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;
use Cbox\Dns\DomainConnect\ProviderSettings;
use Cbox\Dns\DomainConnect\Zone;

it('splits a name into apex and host', function (): void {
    expect(Zone::of('Example.COM.', 'Mail')->fqdn())->toBe('mail.example.com')
        ->and(Zone::of('example.com')->isApex())->toBeTrue()
        ->and(Zone::of('example.com')->fqdn())->toBe('example.com');
});

it('trims whitespace and dots from both zone parts', function (): void {
    $zone = Zone::of(' .Example.com. ', ' .www. ');

    expect($zone->apex)->toBe('example.com')
        ->and($zone->host)->toBe('www')
        ->and($zone->isApex())->toBeFalse();
});

it('reads provider settings with defaults and round-trips them', function (): void {
    $settings = ProviderSettings::fromArray(['providerId' => 'cloudflare.com', 'providerName' => 'Cloudflare', 'urlSyncUX' => 'https://domainconnect.cloudflare.com', 'urlAPI' => 'https://api.cloudflare.com/client/v4/domainconnect']);
    expect($settings->width)->toBe(750)->and($settings->supportsSync())->toBeTrue()
        ->and(ProviderSettings::fromArray($settings->toArray()))->toEqual($settings);
});

it('omits null provider fields and keeps name servers', function (): void {
    $settings = new ProviderSettings('p', 'P', nameServers: ['ns1.p.com', 'ns2.p.com']);

    expect($settings->supportsSync())->toBeFalse()
        ->and($settings->toArray())->toBe(['providerId' => 'p', 'providerName' => 'P', 'width' => 750, 'height' => 750, 'nameServers' => ['ns1.p.com', 'ns2.p.com']])
        ->and(ProviderSettings::fromArray($settings->toArray()))->toEqual($settings);
});

it('rejects malformed provider settings', function (array $payload): void {
    ProviderSettings::fromArray($payload);
})->with([
    'missing id' => [['providerName' => 'X']],
    'name not string' => [['providerId' => 'x', 'providerName' => 5]],
    'url not string' => [['providerId' => 'x', 'providerName' => 'X', 'urlAPI' => 1]],
    'width not int' => [['providerId' => 'x', 'providerName' => 'X', 'width' => '750']],
    'name servers not list of strings' => [['providerId' => 'x', 'providerName' => 'X', 'nameServers' => ['a', 1]]],
])->throws(InvalidPayload::class);

it('round-trips a discovery result, including the not-available case', function (): void {
    $none = new Discovery(Zone::of('example.com'), null, null, new DateTimeImmutable('2026-11-02T10:00:00Z'));
    expect($none->isAvailable())->toBeFalse()->and($none->supportsTemplate())->toBeFalse()
        ->and(Discovery::fromArray($none->toArray()))->toEqual($none);
});

it('round-trips a supported discovery with settings', function (): void {
    $settings = new ProviderSettings('p', 'P', urlSyncUX: 'https://p.example');
    $found = new Discovery(Zone::of('example.com', 'www'), $settings, true, new DateTimeImmutable('2026-11-02T10:00:00+01:00'));

    expect($found->isAvailable())->toBeTrue()->and($found->supportsTemplate())->toBeTrue()
        ->and($found->toArray()['checkedAt'])->toBe('2026-11-02T10:00:00+01:00')
        ->and(Discovery::fromArray($found->toArray()))->toEqual($found);
});

it('accepts a discovery without a settings key and rejects bad types', function (): void {
    $discovery = Discovery::fromArray(['apex' => 'example.com', 'host' => '', 'supported' => null, 'checkedAt' => '2026-11-02T10:00:00+00:00']);

    expect($discovery->settings)->toBeNull();

    Discovery::fromArray(['apex' => 'example.com', 'host' => '', 'supported' => 'yes', 'checkedAt' => '2026-11-02T10:00:00+00:00']);
})->throws(InvalidPayload::class);

it('rejects a discovery with an unparseable timestamp', function (): void {
    Discovery::fromArray(['apex' => 'example.com', 'host' => '', 'checkedAt' => 'not a date']);
})->throws(InvalidPayload::class);

it('parses the redirect back: success has no error; access_denied is a failure', function (): void {
    expect(ApplyOutcome::fromQuery(['state' => 'abc'])->succeeded())->toBeTrue()
        ->and(ApplyOutcome::fromQuery(['state' => 'abc', 'error' => 'access_denied', 'error_description' => 'User cancelled']))
        ->toEqual(new ApplyOutcome('abc', 'access_denied', 'User cancelled'));
});

it('treats non-string query values as absent', function (): void {
    $outcome = ApplyOutcome::fromQuery(['state' => ['a'], 'error' => 5]);

    expect($outcome)->toEqual(new ApplyOutcome)
        ->and($outcome->succeeded())->toBeTrue();
});
