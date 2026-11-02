<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\FakeResolver;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Small offline helpers for the Domain Connect tests.
 */
final class DomainConnectFixture
{
    /** A resolver that answers SOA for `$apex` (and nothing for its sub-names). */
    public static function resolverWithZone(string $apex): FakeResolver
    {
        return (new FakeResolver)->stubRecords($apex, RecordType::SOA, [self::soa($apex)]);
    }

    public static function soa(string $owner): DnsRecord
    {
        return new DnsRecord(RecordType::SOA, $owner, "ns1.{$owner}. hostmaster.{$owner}. 1 7200 3600 1209600 300");
    }
}
