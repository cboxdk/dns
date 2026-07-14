<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Contracts\Clock;
use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\Exceptions\DnssecException;
use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\Support\Der;
use Cbox\Dns\Dnssec\Support\SystemClock;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Verifies one RRSIG over one RRset with one DNSKEY (RFC 4034 §3.1, RFC 5702,
 * RFC 6605, RFC 8080). The DNSSEC protocol work — canonical form, key and
 * signature conversion, algorithm selection, validity window — is done here; the
 * signature MATH is delegated to OpenSSL (RSA/ECDSA) and libsodium (Ed25519). We
 * never implement RSA/ECDSA/EdDSA by hand.
 *
 * Deny-by-default: every checkable failure — unknown or mismatched algorithm,
 * wrong key tag, a non-zone or wrong-protocol key, an out-of-window or malformed
 * signature — returns false. An unrecognised algorithm is a FAILURE, never a
 * pass.
 */
class SignatureVerifier
{
    public function __construct(
        private readonly Clock $clock = new SystemClock,
        private readonly Canonicalizer $canonicalizer = new Canonicalizer,
    ) {}

    /**
     * @param  list<DnsRecord>  $records  the RRset covered by `$rrsig`
     * @param  string|null  $expectedSigner  when set, the RRSIG signer name must
     *                                       equal this zone (case-insensitively);
     *                                       a mismatch is a validation failure
     */
    public function verify(Rrsig $rrsig, RecordType $type, array $records, Dnskey $key, ?string $expectedSigner = null): bool
    {
        try {
            return $this->attempt($rrsig, $type, $records, $key, $expectedSigner);
        } catch (DnssecException) {
            // Any structural/canonicalization failure is a validation failure.
            return false;
        }
    }

    /**
     * True only while `inception <= now <= expiration`, compared with RFC 1982
     * serial arithmetic so the 32-bit timestamps stay correct across the 2106
     * wrap. Exposed so the chain walker can report an expired signature distinctly.
     */
    public function withinValidity(Rrsig $rrsig): bool
    {
        $now = $this->clock->now() & 0xFFFFFFFF;

        return $this->serialLte($rrsig->inception, $now)
            && $this->serialLte($now, $rrsig->expiration);
    }

    /**
     * @param  list<DnsRecord>  $records
     */
    private function attempt(Rrsig $rrsig, RecordType $type, array $records, Dnskey $key, ?string $expectedSigner): bool
    {
        $algorithm = Algorithm::fromCode($rrsig->algorithm);

        if ($algorithm === null) {
            return false; // unknown algorithm → deny
        }

        if ($expectedSigner !== null && ! $this->sameName($rrsig->signerName, $expectedSigner)) {
            return false; // signer name does not match the expected zone
        }

        if ($key->algorithm !== $rrsig->algorithm) {
            return false; // key/signature algorithm mismatch
        }

        if ($key->protocol !== 3 || ! $key->isZoneKey()) {
            return false; // not a usable zone key (RFC 4034 §2.1.1/§2.1.2)
        }

        if (! $rrsig->coversType($type)) {
            return false; // signature does not cover this RRset's type
        }

        if ($key->keyTag() !== $rrsig->keyTag) {
            return false; // candidate key does not match the signature's key tag
        }

        if (! $this->withinValidity($rrsig)) {
            return false; // expired or not yet valid
        }

        $signedData = $this->canonicalizer->signedData($rrsig, $type, $records);

        return match (true) {
            $algorithm->isEd25519() => $this->verifyEd25519($signedData, $rrsig, $key),
            $algorithm->isEcdsa() => $this->verifyEcdsa($signedData, $rrsig, $key, $algorithm),
            $algorithm->isRsa() => $this->verifyRsa($signedData, $rrsig, $key, $algorithm),
            default => false,
        };
    }

    private function verifyRsa(string $data, Rrsig $rrsig, Dnskey $key, Algorithm $algorithm): bool
    {
        [$exponent, $modulus] = $this->splitRsaKey($key->publicKey);

        $pem = Der::rsaPublicKeyPem($exponent, $modulus);
        $digest = $algorithm->opensslDigest();

        if ($digest === null) {
            return false;
        }

        return $this->opensslVerify($data, $rrsig->signature, $pem, $digest);
    }

    private function verifyEcdsa(string $data, Rrsig $rrsig, Dnskey $key, Algorithm $algorithm): bool
    {
        $size = $algorithm->ecdsaComponentSize();
        $digest = $algorithm->opensslDigest();

        if ($size === null || $digest === null) {
            return false;
        }

        if (strlen($key->publicKey) !== $size * 2) {
            return false; // malformed EC point
        }

        $pem = Der::ecPublicKeyPem($key->publicKey, $algorithm);
        $derSignature = Der::ecdsaSignature($rrsig->signature, $size);

        return $this->opensslVerify($data, $derSignature, $pem, $digest);
    }

    private function verifyEd25519(string $data, Rrsig $rrsig, Dnskey $key): bool
    {
        if (strlen($key->publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false; // Ed25519 public key must be 32 octets (RFC 8080)
        }

        if (strlen($rrsig->signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false; // Ed25519 signature must be 64 octets
        }

        return sodium_crypto_sign_verify_detached($rrsig->signature, $data, $key->publicKey);
    }

    private function opensslVerify(string $data, string $signature, string $pem, int $digest): bool
    {
        $publicKey = openssl_pkey_get_public($pem);

        if ($publicKey === false) {
            return false;
        }

        return openssl_verify($data, $signature, $publicKey, $digest) === 1;
    }

    /**
     * Split an RSA DNSKEY public key into [exponent, modulus] (RFC 3110): a
     * one-octet exponent length, or — when that octet is zero — a two-octet
     * length, followed by the exponent and then the modulus.
     *
     * @return array{0: string, 1: string}
     */
    private function splitRsaKey(string $publicKey): array
    {
        $length = strlen($publicKey);

        if ($length < 1) {
            throw MalformedRdata::make('empty RSA public key');
        }

        $exponentLength = ord($publicKey[0]);
        $offset = 1;

        if ($exponentLength === 0) {
            if ($length < 3) {
                throw MalformedRdata::make('truncated RSA exponent length');
            }

            $exponentLength = (ord($publicKey[1]) << 8) | ord($publicKey[2]);
            $offset = 3;
        }

        if ($exponentLength === 0 || $offset + $exponentLength >= $length) {
            throw MalformedRdata::make('RSA exponent runs past end of key');
        }

        $exponent = substr($publicKey, $offset, $exponentLength);
        $modulus = substr($publicKey, $offset + $exponentLength);

        if ($modulus === '') {
            throw MalformedRdata::make('RSA modulus is empty');
        }

        return [$exponent, $modulus];
    }

    /**
     * RFC 1982 "serial number arithmetic": true when `$a <= $b` within the 32-bit
     * circular space (difference below 2^31).
     */
    private function serialLte(int $a, int $b): bool
    {
        return (($b - $a) & 0xFFFFFFFF) < 0x80000000;
    }

    private function sameName(string $a, string $b): bool
    {
        return strcasecmp(rtrim($a, '.'), rtrim($b, '.')) === 0;
    }
}
