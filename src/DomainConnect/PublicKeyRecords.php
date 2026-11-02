<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;

/**
 * The TXT record strings a template provider publishes its signing public key
 * in (`p=<n>,a=RS256,d=<base64 chunk>`), and the reverse: rebuilding the PEM
 * from those strings in any order.
 */
class PublicKeyRecords
{
    /** 255 bytes per TXT string minus the `p=NN,a=RS256,d=` prefix with room for two-digit parts. */
    public const int MAX_CHUNK = 235;

    /**
     * @return list<string>
     */
    public static function for(string $publicKeyPem, int $chunk = 200): array
    {
        if ($chunk < 1 || $chunk > self::MAX_CHUNK) {
            throw InvalidPayload::because('public key chunk size must be between 1 and '.self::MAX_CHUNK);
        }

        $body = preg_replace('/-----[A-Z ]+-----|\s+/', '', $publicKeyPem);

        if (! is_string($body) || $body === '') {
            throw InvalidPayload::because('public key PEM has no body');
        }

        $records = [];

        foreach (str_split($body, $chunk) as $index => $piece) {
            $records[] = 'p='.($index + 1).',a=RS256,d='.$piece;
        }

        return $records;
    }

    /**
     * @param  list<string>  $records
     */
    public static function toPem(array $records): string
    {
        $parts = [];

        foreach ($records as $record) {
            $fields = [];

            foreach (explode(',', $record) as $pair) {
                $kv = explode('=', $pair, 2);

                if (count($kv) === 2) {
                    $fields[trim($kv[0])] = trim($kv[1]);
                }
            }

            $p = $fields['p'] ?? '';
            $d = $fields['d'] ?? '';

            if (! ctype_digit($p) || $d === '') {
                throw InvalidPayload::because('public key record must carry p= and d=');
            }

            $parts[(int) $p] = $d;
        }

        ksort($parts);

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(implode('', $parts), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }
}
