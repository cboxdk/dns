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
    /** A TXT string holds 255 bytes; `p=NN,a=RS256,d=` takes 15, leaving 240. 235 keeps a margin. */
    public const int MAX_CHUNK = 235;

    /**
     * Accepts an RSA public key in any PEM form OpenSSL reads (SPKI or PKCS#1)
     * and always publishes its SPKI (`BEGIN PUBLIC KEY`) body. Anything else,
     * a private key included, is refused so it can never end up in DNS.
     *
     * @return list<string>
     */
    public static function for(string $publicKeyPem, int $chunk = 200): array
    {
        if ($chunk < 1 || $chunk > self::MAX_CHUNK) {
            throw InvalidPayload::because('public key chunk size must be between 1 and '.self::MAX_CHUNK);
        }

        $key = openssl_pkey_get_public($publicKeyPem);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ! is_string($details['key'] ?? null)) {
            throw InvalidPayload::because('expected an RSA public key PEM');
        }

        $body = preg_replace('/-----[A-Z ]+-----|\s+/', '', $details['key']);

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
                    $fields[trim($kv[0])] = $kv[1];
                }
            }

            $p = trim($fields['p'] ?? '');
            $d = preg_replace('/\s+/', '', $fields['d'] ?? '');

            if (! ctype_digit($p) || (int) $p < 1 || ! is_string($d) || $d === '') {
                throw InvalidPayload::because('public key record must carry p= (from 1) and d=');
            }

            if (isset($fields['a']) && trim($fields['a']) !== 'RS256') {
                throw InvalidPayload::because('public key record algorithm must be RS256');
            }

            if (isset($parts[(int) $p])) {
                throw InvalidPayload::because("public key record p={$p} appears twice");
            }

            $parts[(int) $p] = $d;
        }

        ksort($parts);

        if ($parts === [] || array_keys($parts) !== range(1, count($parts))) {
            throw InvalidPayload::because('public key records must be numbered 1..n without gaps');
        }

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(implode('', $parts), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }
}
