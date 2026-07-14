<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Records;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed RRSIG RR (RFC 4034 §3). Carries every field of the signature plus the
 * exact prefix — the RDATA up to but excluding the signature octets — that must
 * be prepended to the canonical RRset when reconstructing the signed message.
 */
final readonly class Rrsig
{
    private function __construct(
        public int $typeCovered,
        public int $algorithm,
        public int $labels,
        public int $originalTtl,
        public int $expiration,
        public int $inception,
        public int $keyTag,
        public string $signerName,
        public string $signature,
        public string $signedPrefix,
    ) {}

    /**
     * Parse from the exact on-wire RRSIG RDATA bytes. The signer name is read as
     * an uncompressed wire name (RFC 4034 §3.1.7); a compression pointer here is
     * rejected via {@see WireName::read()}.
     */
    public static function fromRdata(string $rdata): self
    {
        if (strlen($rdata) < 18) {
            throw MalformedRdata::make('RRSIG RDATA shorter than 18 octets');
        }

        $typeCovered = (ord($rdata[0]) << 8) | ord($rdata[1]);
        $algorithm = ord($rdata[2]);
        $labels = ord($rdata[3]);
        $originalTtl = self::uint32($rdata, 4);
        $expiration = self::uint32($rdata, 8);
        $inception = self::uint32($rdata, 12);
        $keyTag = (ord($rdata[16]) << 8) | ord($rdata[17]);

        [$signerName, $offset] = WireName::read($rdata, 18);

        $signature = substr($rdata, $offset);

        if ($signature === '') {
            throw MalformedRdata::make('RRSIG RDATA has empty signature');
        }

        // The signed data begins with the RRSIG RDATA up to and including the
        // signer name, i.e. everything before the signature octets.
        $signedPrefix = substr($rdata, 0, $offset);

        return new self(
            $typeCovered,
            $algorithm,
            $labels,
            $originalTtl,
            $expiration,
            $inception,
            $keyTag,
            $signerName,
            $signature,
            $signedPrefix,
        );
    }

    public function coversType(RecordType $type): bool
    {
        return $this->typeCovered === $type->code();
    }

    private static function uint32(string $data, int $offset): int
    {
        return (ord($data[$offset]) << 24)
            | (ord($data[$offset + 1]) << 16)
            | (ord($data[$offset + 2]) << 8)
            | ord($data[$offset + 3]);
    }
}
