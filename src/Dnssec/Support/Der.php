<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;

/**
 * Minimal DER (ASN.1) encoder for the one job DNSSEC needs: turning a DNSKEY's
 * raw public-key octets into a SubjectPublicKeyInfo that OpenSSL will load, and
 * turning an ECDSA RRSIG's raw r‖s signature into the DER SEQUENCE OpenSSL
 * expects. We build the exact structures — never hand-roll the signature math.
 */
class Der
{
    // rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
    private const string RSA_ALGID = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    // id-ecPublicKey (1.2.840.10045.2.1).
    private const string EC_PUBLIC_KEY_OID = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";

    // prime256v1 / P-256 (1.2.840.10045.3.1.7).
    private const string P256_OID = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    // secp384r1 / P-384 (1.3.132.0.34).
    private const string P384_OID = "\x06\x05\x2b\x81\x04\x00\x22";

    /**
     * Build a PEM-encoded RSA SubjectPublicKeyInfo from the DNSKEY's exponent and
     * modulus octets (RFC 3110 / RFC 5702), ready for `openssl_pkey_get_public`.
     */
    public static function rsaPublicKeyPem(string $exponent, string $modulus): string
    {
        $rsaPublicKey = self::sequence(
            self::integer($modulus).self::integer($exponent),
        );

        $spki = self::sequence(self::RSA_ALGID.self::bitString($rsaPublicKey));

        return self::pem($spki);
    }

    /**
     * Build a PEM-encoded EC SubjectPublicKeyInfo from the DNSKEY's raw X‖Y point
     * (RFC 6605). The point is encoded uncompressed (leading 0x04).
     */
    public static function ecPublicKeyPem(string $rawPoint, Algorithm $algorithm): string
    {
        $curveOid = match ($algorithm) {
            Algorithm::ECDSAP256SHA256 => self::P256_OID,
            Algorithm::ECDSAP384SHA384 => self::P384_OID,
            default => throw MalformedRdata::make('non-ECDSA algorithm passed to EC SPKI builder'),
        };

        $algId = self::sequence(self::EC_PUBLIC_KEY_OID.$curveOid);
        $point = "\x04".$rawPoint; // uncompressed EC point
        $spki = self::sequence($algId.self::bitString($point));

        return self::pem($spki);
    }

    /**
     * Convert an ECDSA RRSIG signature (raw r‖s, each `$size` octets, RFC 6605)
     * into the DER `SEQUENCE { INTEGER r, INTEGER s }` OpenSSL requires.
     */
    public static function ecdsaSignature(string $rawSignature, int $size): string
    {
        if (strlen($rawSignature) !== $size * 2) {
            throw MalformedRdata::make('ECDSA signature length does not match curve');
        }

        $r = substr($rawSignature, 0, $size);
        $s = substr($rawSignature, $size);

        return self::sequence(self::integer($r).self::integer($s));
    }

    /**
     * DER SEQUENCE (tag 0x30) wrapping the already-encoded contents.
     */
    private static function sequence(string $contents): string
    {
        return "\x30".self::length(strlen($contents)).$contents;
    }

    /**
     * DER INTEGER (tag 0x02) for an unsigned big-endian value: strip leading zero
     * octets, then prepend a 0x00 if the high bit is set so the value stays
     * positive.
     */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '') {
            $bytes = "\x00";
        }

        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".self::length(strlen($bytes)).$bytes;
    }

    /**
     * DER BIT STRING (tag 0x03) with zero unused bits.
     */
    private static function bitString(string $contents): string
    {
        $contents = "\x00".$contents;

        return "\x03".self::length(strlen($contents)).$contents;
    }

    /**
     * DER definite-length octets (short form under 128, else long form). Length is
     * a byte count, always non-negative; the guard keeps that provable.
     */
    private static function length(int $length): string
    {
        if ($length < 0) {
            throw MalformedRdata::make('negative DER length');
        }

        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF).$bytes;
            $length >>= 8;
        }

        // Long-form leading octet: 0x80 | number-of-length-octets (< 128).
        return chr(0x80 | (strlen($bytes) & 0x7F)).$bytes;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($der), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }
}
