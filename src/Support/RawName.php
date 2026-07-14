<?php

declare(strict_types=1);

namespace Cbox\Dns\Support;

use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Reads an uncompressed domain name out of a slice of raw RDATA — the form value
 * objects use when they parse from {@see DnsRecord::$raw}
 * (RFC 3597 forbids compression in the RDATA of types defined after RFC 1035).
 */
final class RawName
{
    /**
     * Read a name starting at `$offset`, advancing it past the terminating root
     * label. Returns null on a compression pointer or an out-of-bounds label.
     */
    public static function read(string $raw, int &$offset): ?string
    {
        $labels = [];
        $length = strlen($raw);

        while ($offset < $length) {
            $labelLength = ord($raw[$offset]);
            $offset++;

            if ($labelLength === 0) {
                return $labels === [] ? '.' : implode('.', $labels);
            }

            if (($labelLength & 0xC0) === 0xC0 || $offset + $labelLength > $length) {
                return null;
            }

            $labels[] = substr($raw, $offset, $labelLength);
            $offset += $labelLength;
        }

        return null; // ran out of bytes before the root label
    }
}
