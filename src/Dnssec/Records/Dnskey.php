<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Records;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;

/**
 * A parsed DNSKEY RR (RFC 4034 §2). Holds the flags, protocol, algorithm, and the
 * raw public-key octets, plus the verbatim RDATA needed for the RFC 4034 App. B
 * key-tag computation and for DS digesting.
 */
final readonly class Dnskey
{
    private function __construct(
        public int $flags,
        public int $protocol,
        public int $algorithm,
        public string $publicKey,
        public string $rdata,
    ) {}

    /**
     * Parse from the exact on-wire DNSKEY RDATA bytes.
     */
    public static function fromRdata(string $rdata): self
    {
        if (strlen($rdata) < 4) {
            throw MalformedRdata::make('DNSKEY RDATA shorter than 4 octets');
        }

        $flags = (ord($rdata[0]) << 8) | ord($rdata[1]);
        $protocol = ord($rdata[2]);
        $algorithm = ord($rdata[3]);
        $publicKey = substr($rdata, 4);

        return new self($flags, $protocol, $algorithm, $publicKey, $rdata);
    }

    /**
     * The RFC 4034 Appendix B key tag: a 16-bit checksum over the whole RDATA,
     * summing each octet into alternating high/low bytes of a 32-bit accumulator,
     * then folding the carry back in. This is NOT collision-free — the verifier
     * uses it only to pre-select candidate keys, never as proof of identity.
     */
    public function keyTag(): int
    {
        $sum = 0;
        $length = strlen($this->rdata);

        for ($i = 0; $i < $length; $i++) {
            $sum += ($i & 1) === 0
                ? ord($this->rdata[$i]) << 8
                : ord($this->rdata[$i]);
        }

        $sum += ($sum >> 16) & 0xFFFF;

        return $sum & 0xFFFF;
    }

    /**
     * The Zone Key flag (bit 7): the key may be used to verify zone data. A DNSKEY
     * without it MUST NOT be used for DNSSEC validation (RFC 4034 §2.1.1).
     */
    public function isZoneKey(): bool
    {
        return ($this->flags & 0x0100) !== 0;
    }

    /**
     * The Secure Entry Point flag (bit 15): conventionally set on a KSK — the key
     * a parent DS points at (RFC 4034 §2.1.1 / RFC 3757).
     */
    public function isSecureEntryPoint(): bool
    {
        return ($this->flags & 0x0001) !== 0;
    }
}
