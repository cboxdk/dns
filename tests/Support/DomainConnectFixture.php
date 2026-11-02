<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\DomainConnect\Discoverer;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\ZoneLocator;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Small offline helpers for the Domain Connect tests.
 */
final class DomainConnectFixture
{
    /** 2026-11-02T10:00:00Z */
    public const int NOW = 1793613600;

    public const string API_ADDRESS = '203.0.113.20';

    public const string SETTINGS_URL = 'https://dc.cloudflare.example/v2/acme.example/settings';

    public const string SUPPORT_URL = 'https://api.cloudflare.example/v2/domainTemplates/providers/cbox.dk/services/engage-sending';

    public const array SETTINGS = [
        'providerId' => 'cloudflare.com',
        'providerName' => 'Cloudflare',
        'urlSyncUX' => 'https://dc.cloudflare.example',
        'urlAPI' => 'https://api.cloudflare.example',
    ];

    /** A resolver that answers SOA for `$apex` (and nothing for its sub-names). */
    public static function resolverWithZone(string $apex): FakeResolver
    {
        return (new FakeResolver)->stubRecords($apex, RecordType::SOA, [self::soa($apex)]);
    }

    /** The Task 1 fixture template (`cbox.dk` / `engage-sending`). */
    public static function engageTemplate(): Template
    {
        $json = file_get_contents(__DIR__.'/../Fixtures/domain-connect/cbox.dk.engage-sending.json');

        if ($json === false) {
            throw new \RuntimeException('Missing the engage-sending template fixture.');
        }

        return Template::fromJson($json);
    }

    /** A resolver for acme.example whose `_domainconnect` TXT is `$txt`, whose `$host` has A `$address`, and whose provider API host has a public A. */
    public static function discoveryResolver(string $txt = 'dc.cloudflare.example', string $address = '203.0.113.10', string $host = 'dc.cloudflare.example'): FakeResolver
    {
        return self::resolverWithZone('acme.example')
            ->stub('_domainconnect.acme.example', RecordType::TXT, [$txt])
            ->stub($host, RecordType::A, [$address])
            ->stub('api.cloudflare.example', RecordType::A, [self::API_ADDRESS]);
    }

    public static function discoverer(FakeResolver $resolver, FakeTransport $http, bool $allowNonPublicHosts = false): Discoverer
    {
        return new Discoverer($resolver, $http, new ZoneLocator($resolver), new FrozenClock(self::NOW), $allowNonPublicHosts);
    }

    public static function soa(string $owner): DnsRecord
    {
        return new DnsRecord(RecordType::SOA, $owner, "ns1.{$owner}. hostmaster.{$owner}. 1 7200 3600 1209600 300");
    }
}
