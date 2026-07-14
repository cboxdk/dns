<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;

/**
 * Decoder for the NSEC/NSEC3 Type Bit Maps field (RFC 4034 §4.1.2): a series of
 * windows, each `window-number, length, bitmap` where a set bit at position N of
 * window W means RR type `W*256 + N` is present at the owner name.
 */
class TypeBitmap
{
    /**
     * @return array<int, true> the set of present RR type codes, as a set keyed
     *                          by type code
     */
    public static function parse(string $bytes): array
    {
        $types = [];
        $offset = 0;
        $length = strlen($bytes);

        while ($offset < $length) {
            if ($offset + 2 > $length) {
                throw MalformedRdata::make('truncated type-bitmap window header');
            }

            $window = ord($bytes[$offset]);
            $bitmapLength = ord($bytes[$offset + 1]);
            $offset += 2;

            if ($bitmapLength < 1 || $bitmapLength > 32) {
                throw MalformedRdata::make('type-bitmap window length out of range');
            }

            if ($offset + $bitmapLength > $length) {
                throw MalformedRdata::make('truncated type-bitmap window');
            }

            for ($i = 0; $i < $bitmapLength; $i++) {
                $octet = ord($bytes[$offset + $i]);

                for ($bit = 0; $bit < 8; $bit++) {
                    if (($octet & (0x80 >> $bit)) !== 0) {
                        $types[($window * 256) + ($i * 8) + $bit] = true;
                    }
                }
            }

            $offset += $bitmapLength;
        }

        return $types;
    }
}
