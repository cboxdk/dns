<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\Support\Base32Hex;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Builders for constructed NSEC/NSEC3 records used to exercise denial-of-existence
 * proofs offline. The type bitmaps and hashed owner names are assembled exactly
 * as they appear on the wire (RFC 4034 §4.1.2, RFC 5155 §3).
 */
final class DenialFixtures
{
    /**
     * @param  list<RecordType>  $types
     */
    public static function nsec(string $owner, string $next, array $types): DnsRecord
    {
        // Next-domain name is uncompressed and NOT down-cased (RFC 6840 §5.1); the
        // builder keeps it verbatim.
        $rdata = WireName::encode($next, false).self::typeBitmap($types);

        return new DnsRecord(RecordType::NSEC, $owner, base64_encode($rdata), 3600, null, $rdata);
    }

    /**
     * @param  list<RecordType>  $types
     */
    public static function nsec3(
        string $ownerHash,
        string $nextHash,
        int $iterations,
        string $salt,
        array $types,
        string $zone,
        bool $optOut = false,
    ): DnsRecord {
        $rdata = chr(1)                                   // hash algorithm = SHA-1
            .chr($optOut ? 0x01 : 0x00)                   // flags
            .pack('n', $iterations)
            .chr(strlen($salt)).$salt
            .chr(strlen($nextHash)).$nextHash
            .self::typeBitmap($types);

        $owner = Base32Hex::encode($ownerHash).'.'.$zone;

        return new DnsRecord(RecordType::NSEC3, $owner, base64_encode($rdata), 3600, null, $rdata);
    }

    /**
     * @param  list<RecordType>  $types
     */
    public static function typeBitmap(array $types): string
    {
        /** @var array<int, array<int, int>> $windows */
        $windows = [];

        foreach ($types as $type) {
            $code = $type->code();
            $window = intdiv($code, 256);
            $bit = $code % 256;
            $windows[$window][intdiv($bit, 8)] = ($windows[$window][intdiv($bit, 8)] ?? 0) | (0x80 >> ($bit % 8));
        }

        ksort($windows);
        $out = '';

        foreach ($windows as $window => $octets) {
            $length = max(array_keys($octets)) + 1;
            $bitmap = '';

            for ($i = 0; $i < $length; $i++) {
                $bitmap .= chr($octets[$i] ?? 0);
            }

            $out .= chr($window).chr($length).$bitmap;
        }

        return $out;
    }
}
