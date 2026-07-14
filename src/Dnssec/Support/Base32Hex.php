<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;

/**
 * Base32hex ("extended hex", RFC 4648 §7) codec — the encoding NSEC3 uses for
 * hashed owner names (RFC 5155 §1.3). Case-insensitive on decode.
 */
final class Base32Hex
{
    private const string ALPHABET = '0123456789abcdefghijklmnopqrstuv';

    public static function encode(string $bytes): string
    {
        $buffer = 0;
        $bitsLeft = 0;
        $out = '';

        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bitsLeft += 8;

            while ($bitsLeft >= 5) {
                $bitsLeft -= 5;
                $out .= self::ALPHABET[($buffer >> $bitsLeft) & 0x1F];
            }
        }

        if ($bitsLeft > 0) {
            $out .= self::ALPHABET[($buffer << (5 - $bitsLeft)) & 0x1F];
        }

        return $out;
    }

    public static function decode(string $text): string
    {
        $text = strtolower($text);
        $buffer = 0;
        $bitsLeft = 0;
        $out = '';

        for ($i = 0, $n = strlen($text); $i < $n; $i++) {
            $index = strpos(self::ALPHABET, $text[$i]);

            if ($index === false) {
                throw MalformedRdata::make('invalid base32hex character in NSEC3 owner');
            }

            $buffer = ($buffer << 5) | $index;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $out .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $out;
    }
}
