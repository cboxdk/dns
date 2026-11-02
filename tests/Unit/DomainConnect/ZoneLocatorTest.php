<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Exceptions\ZoneNotFound;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\DomainConnect\ZoneLocator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\Tests\Support\DomainConnectFixture;
use Cbox\Dns\ValueObjects\DnsResponse;

it('finds the apex below a subdomain and returns the host part', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stub('mail.acme.example', RecordType::SOA, []);

    expect((new ZoneLocator($fake))->locate('Mail.Acme.Example.'))->toEqual(Zone::of('acme.example', 'mail'));
});

it('returns the apex with an empty host when the name is the zone', function (): void {
    $zone = (new ZoneLocator(DomainConnectFixture::resolverWithZone('acme.example')))->locate('acme.example');

    expect($zone)->toEqual(Zone::of('acme.example'))
        ->and($zone->host)->toBe('');
});

it('keeps every removed label in the host part', function (): void {
    $zone = (new ZoneLocator(DomainConnectFixture::resolverWithZone('acme.example')))->locate('a.b.acme.example');

    expect($zone)->toEqual(Zone::of('acme.example', 'a.b'));
});

it('throws ZoneNotFound when no SOA answers up the tree', function (): void {
    expect(fn () => (new ZoneLocator(new FakeResolver))->locate('nothing.invalid'))->toThrow(ZoneNotFound::class);
});

it('ignores a SOA that belongs to a parent (the authority section case)', function (): void {
    $fake = DomainConnectFixture::resolverWithZone('acme.example')
        ->stubRecords('mail.acme.example', RecordType::SOA, [DomainConnectFixture::soa('acme.example')]);

    expect((new ZoneLocator($fake))->locate('mail.acme.example'))->toEqual(Zone::of('acme.example', 'mail'));
});

it('treats a thrown DnsException as no SOA here and keeps walking', function (): void {
    $resolver = new class extends FakeResolver
    {
        public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
        {
            if ($host === 'mail.acme.example') {
                throw ResolutionFailed::make('192.0.2.1', 'timed out');
            }

            return parent::query($host, $type, $nameserver, $recursion, $dnssec);
        }
    };
    $resolver->stubRecords('acme.example', RecordType::SOA, [DomainConnectFixture::soa('acme.example')]);

    expect((new ZoneLocator($resolver))->locate('mail.acme.example')->apex)->toBe('acme.example');
});
