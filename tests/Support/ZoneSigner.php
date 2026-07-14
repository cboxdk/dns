<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\Canonicalizer;
use Cbox\Dns\Dnssec\Enums\Algorithm;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Ds;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * A test-only DNSSEC signer: generates a real keypair for a given algorithm and
 * produces genuinely-signed DNSKEY/RRSIG/DS records, so the verifier and chain
 * walker can be exercised offline against real OpenSSL/libsodium signatures for
 * algorithms we have no captured public fixture for (RSA, ECDSA P-384, Ed25519).
 *
 * The math here (openssl_sign / sodium_crypto_sign_detached) is the inverse of
 * the production verifier; it is never used in `src/`.
 */
final class ZoneSigner
{
    private readonly string $publicKeyRdata;

    private readonly ?OpenSSLAsymmetricKey $privateKey;

    private readonly string $sodiumSecret;

    public function __construct(
        public readonly Algorithm $algorithm,
        public readonly string $zone,
        public readonly int $flags = 257,
    ) {
        [$this->publicKeyRdata, $this->privateKey, $this->sodiumSecret] = $this->generate();
    }

    public function dnskeyRecord(): DnsRecord
    {
        $rdata = $this->dnskeyRdata();

        return new DnsRecord(RecordType::DNSKEY, $this->zone, base64_encode($rdata), 3600, null, $rdata);
    }

    public function dnskey(): Dnskey
    {
        return Dnskey::fromRdata($this->dnskeyRdata());
    }

    public function keyTag(): int
    {
        return $this->dnskey()->keyTag();
    }

    /**
     * Sign an RRset, returning the RRSIG record. The signed data is reconstructed
     * with the production {@see Canonicalizer} (the captured cloudflare vector is
     * the independent proof that canonicalisation itself is correct).
     *
     * @param  list<DnsRecord>  $rrset
     */
    public function signRrset(
        RecordType $type,
        array $rrset,
        int $inception = 1_700_000_000,
        int $expiration = 4_000_000_000,
        int $originalTtl = 3600,
        ?int $labels = null,
    ): DnsRecord {
        $owner = $rrset[0]->name;
        $labels ??= $this->labelCount($owner);

        $prefix = pack('n', $type->code())
            .chr($this->algorithm->value)
            .chr($labels)
            .pack('N', $originalTtl)
            .pack('N', $expiration)
            .pack('N', $inception)
            .pack('n', $this->keyTag())
            .WireName::canonical($this->zone);

        $rrsig = Rrsig::fromRdata($prefix."\x00"); // dummy sig, only prefix used
        $signedData = (new Canonicalizer)->signedData($rrsig, $type, $rrset);

        $signature = $this->sign($signedData);
        $rdata = $prefix.$signature;

        return new DnsRecord(RecordType::RRSIG, $owner, base64_encode($rdata), $originalTtl, null, $rdata);
    }

    public function dsRecord(int $digestType = 2): DnsRecord
    {
        $rdata = $this->dsRdata($digestType);

        return new DnsRecord(RecordType::DS, $this->zone, base64_encode($rdata), 86400, null, $rdata);
    }

    public function ds(int $digestType = 2): Ds
    {
        return Ds::fromRdata($this->dsRdata($digestType));
    }

    private function dnskeyRdata(): string
    {
        return pack('n', $this->flags).chr(3).chr($this->algorithm->value).$this->publicKeyRdata;
    }

    private function dsRdata(int $digestType): string
    {
        $algo = $digestType === 4 ? 'sha384' : 'sha256';
        $digest = hash($algo, WireName::canonical($this->zone).$this->dnskeyRdata(), true);

        return pack('n', $this->keyTag()).chr($this->algorithm->value).chr($digestType).$digest;
    }

    private function sign(string $data): string
    {
        if ($this->algorithm->isEd25519()) {
            return sodium_crypto_sign_detached($data, $this->sodiumSecret);
        }

        if ($this->privateKey === null) {
            throw new RuntimeException('missing private key');
        }

        $digest = $this->algorithm->opensslDigest();

        if ($digest === null) {
            throw new RuntimeException('no digest for algorithm');
        }

        $signature = '';

        if (! openssl_sign($data, $signature, $this->privateKey, $digest)) {
            throw new RuntimeException('openssl_sign failed');
        }

        if ($this->algorithm->isEcdsa()) {
            $size = $this->algorithm->ecdsaComponentSize() ?? 0;

            return $this->ecdsaDerToRaw($signature, $size);
        }

        return $signature;
    }

    /**
     * @return array{0: string, 1: OpenSSLAsymmetricKey|null, 2: string}
     */
    private function generate(): array
    {
        if ($this->algorithm->isEd25519()) {
            $pair = sodium_crypto_sign_keypair();

            return [sodium_crypto_sign_publickey($pair), null, sodium_crypto_sign_secretkey($pair)];
        }

        if ($this->algorithm->isEcdsa()) {
            return $this->generateEcdsa();
        }

        return $this->generateRsa();
    }

    /**
     * @return array{0: string, 1: OpenSSLAsymmetricKey, 2: string}
     */
    private function generateRsa(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        if ($key === false) {
            throw new RuntimeException('RSA key generation failed');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('RSA details unavailable');
        }

        $modulus = (string) $details['rsa']['n'];
        $exponent = (string) $details['rsa']['e'];

        // RFC 3110: one-octet exponent length (exponents here are 3 octets).
        $publicKey = chr(strlen($exponent)).$exponent.$modulus;

        return [$publicKey, $key, ''];
    }

    /**
     * @return array{0: string, 1: OpenSSLAsymmetricKey, 2: string}
     */
    private function generateEcdsa(): array
    {
        $curve = $this->algorithm === Algorithm::ECDSAP256SHA256 ? 'prime256v1' : 'secp384r1';
        $size = $this->algorithm->ecdsaComponentSize() ?? 0;

        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);

        if ($key === false) {
            throw new RuntimeException('EC key generation failed');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['ec']['x'], $details['ec']['y'])) {
            throw new RuntimeException('EC details unavailable');
        }

        $x = str_pad((string) $details['ec']['x'], $size, "\x00", STR_PAD_LEFT);
        $y = str_pad((string) $details['ec']['y'], $size, "\x00", STR_PAD_LEFT);

        return [$x.$y, $key, ''];
    }

    private function ecdsaDerToRaw(string $der, int $size): string
    {
        $offset = 0;

        $this->expect($der, $offset, 0x30); // SEQUENCE
        $this->readLength($der, $offset);

        $r = $this->readInteger($der, $offset);
        $s = $this->readInteger($der, $offset);

        return str_pad($r, $size, "\x00", STR_PAD_LEFT).str_pad($s, $size, "\x00", STR_PAD_LEFT);
    }

    private function readInteger(string $der, int &$offset): string
    {
        $this->expect($der, $offset, 0x02); // INTEGER
        $length = $this->readLength($der, $offset);
        $value = substr($der, $offset, $length);
        $offset += $length;

        return ltrim($value, "\x00");
    }

    private function expect(string $der, int &$offset, int $tag): void
    {
        if (ord($der[$offset]) !== $tag) {
            throw new RuntimeException('unexpected DER tag');
        }

        $offset++;
    }

    private function readLength(string $der, int &$offset): int
    {
        $first = ord($der[$offset]);
        $offset++;

        if ($first < 0x80) {
            return $first;
        }

        $bytes = $first & 0x7F;
        $length = 0;

        for ($i = 0; $i < $bytes; $i++) {
            $length = ($length << 8) | ord($der[$offset]);
            $offset++;
        }

        return $length;
    }

    private function labelCount(string $name): int
    {
        $name = trim($name, '.');

        return $name === '' ? 0 : count(explode('.', $name));
    }
}
