<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\Testing\FrozenClock;
use Cbox\Dns\DomainConnect\Discoverer;
use Cbox\Dns\DomainConnect\RecordSet;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;
use Cbox\Dns\DomainConnect\Zone;
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

    public const string NS_IP = '192.0.2.1';

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

    /** A resolver that lets AuthoritativeResolver find one authoritative server (`ns1.<apex>` at `$ip`) for `$apex`. */
    public static function withAuthoritativeZone(string $apex, string $ip = '192.0.2.1'): FakeResolver
    {
        return (new FakeResolver)
            ->stub($apex, RecordType::NS, ["ns1.{$apex}"])
            ->stub("ns1.{$apex}", RecordType::A, [$ip]);
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

    /** @return array<string, string> */
    public static function engageVariables(): array
    {
        return ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => 'MIGf'];
    }

    /**
     * The engage-sending template with its records replaced by `$records`.
     *
     * @param  list<array<string, mixed>>  $records
     */
    public static function templateWithRecords(array $records): Template
    {
        return Template::fromArray([...self::engageTemplate()->toArray(), 'records' => $records]);
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

    /** The engage-sending template expanded for the apex of acme.example. */
    public static function engageSet(): RecordSet
    {
        return RecordSet::fromTemplate(self::engageTemplate(), Zone::of('acme.example'), self::engageVariables());
    }

    /** Stubs the MX at send.acme.example on the authoritative server. */
    public static function mxAt(FakeResolver $fake, string $target, int $priority): FakeResolver
    {
        return $fake->stubRecords('send.acme.example', RecordType::MX, [new DnsRecord(RecordType::MX, 'send.acme.example', $target, priority: $priority)], nameserver: self::NS_IP);
    }

    /**
     * An acme.example zone carrying every engage-sending record.
     *
     * @param  list<string>  $spf
     */
    public static function liveZone(string $mx = 'feedback-smtp.eu-west-1.amazonses.com.', array $spf = ['v=spf1 include:amazonses.com ~all']): FakeResolver
    {
        return self::mxAt(self::withAuthoritativeZone('acme.example', self::NS_IP), $mx, 10)
            ->stub('send.acme.example', RecordType::TXT, $spf, nameserver: self::NS_IP)
            ->stub('resend._domainkey.acme.example', RecordType::TXT, ['p=MIGf'], nameserver: self::NS_IP)
            ->stub('_dmarc.acme.example', RecordType::TXT, ['v=DMARC1; p=quarantine'], nameserver: self::NS_IP);
    }

    /** A file from tests/Fixtures/domain-connect (the test-only keypair, the reference signature). */
    public static function file(string $name): string
    {
        $contents = file_get_contents(__DIR__.'/../Fixtures/domain-connect/'.$name);

        if ($contents === false) {
            throw new \RuntimeException("Missing the Domain Connect fixture [{$name}].");
        }

        return $contents;
    }

    public static function soa(string $owner): DnsRecord
    {
        return new DnsRecord(RecordType::SOA, $owner, "ns1.{$owner}. hostmaster.{$owner}. 1 7200 3600 1209600 300");
    }
}
