<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;
use Cbox\Dns\Protocol\Reader;

/**
 * Domain-name wire codec for DNSSEC use. Unlike the general {@see Reader},
 * this never follows compression pointers: names inside signed RDATA and RRSIG
 * signer fields must be uncompressed (RFC 4034 §6.2), so a pointer here is a
 * hard error, not something to silently resolve.
 */
class WireName
{
    /**
     * Encode a dotted name to length-prefixed wire labels terminated by the root.
     * With `$lowercase` on, ASCII A–Z in each label are down-cased for canonical
     * form (RFC 4034 §6.2); the length octets are untouched.
     */
    public static function encode(string $name, bool $lowercase): string
    {
        $name = trim($name, '.');

        if ($name === '') {
            return "\x00";
        }

        $encoded = '';

        foreach (explode('.', $name) as $label) {
            $length = strlen($label);

            if ($length > 63) {
                throw MalformedRdata::make('label exceeds 63 octets');
            }

            if ($lowercase) {
                $label = self::downcase($label);
            }

            $encoded .= chr($length).$label;
        }

        return $encoded."\x00";
    }

    /**
     * Read one uncompressed wire name from `$data` starting at `$offset`.
     *
     * @return array{0: string, 1: int} the dotted name (no trailing dot) and the
     *                                  offset just past the root label
     */
    public static function read(string $data, int $offset): array
    {
        $labels = [];
        $length = strlen($data);

        while (true) {
            if ($offset >= $length) {
                throw MalformedRdata::make('name runs past end of RDATA');
            }

            $len = ord($data[$offset]);

            if (($len & 0xC0) !== 0) {
                // Either a compression pointer (0xC0) or an unsupported EDNS0
                // label type — neither is legal in uncompressed signed RDATA.
                throw MalformedRdata::make('compression pointer or extended label in signed name');
            }

            $offset++;

            if ($len === 0) {
                break;
            }

            if ($offset + $len > $length) {
                throw MalformedRdata::make('label runs past end of RDATA');
            }

            $labels[] = substr($data, $offset, $len);
            $offset += $len;
        }

        return [implode('.', $labels), $offset];
    }

    /**
     * The canonical wire form of a name: uncompressed labels, ASCII down-cased,
     * root-terminated (RFC 4034 §6.1 / §6.2).
     */
    public static function canonical(string $name): string
    {
        return self::encode($name, true);
    }

    private static function downcase(string $label): string
    {
        $out = '';

        for ($i = 0, $n = strlen($label); $i < $n; $i++) {
            $c = ord($label[$i]);
            $out .= chr($c >= 0x41 && $c <= 0x5A ? $c + 0x20 : $c);
        }

        return $out;
    }
}
