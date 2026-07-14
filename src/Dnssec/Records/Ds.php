<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Records;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;

/**
 * A parsed DS RR (RFC 4034 §5): the delegation link a parent zone publishes to
 * commit to a child's KSK. `digest` is the raw hash octets over the child DNSKEY.
 */
final readonly class Ds
{
    private function __construct(
        public int $keyTag,
        public int $algorithm,
        public int $digestType,
        public string $digest,
    ) {}

    /**
     * Build a DS from its individual fields — used for hard-coded trust anchors
     * and test vectors, where the parts are known rather than parsed from wire.
     */
    public static function fromParts(int $keyTag, int $algorithm, int $digestType, string $digest): self
    {
        if ($digest === '') {
            throw MalformedRdata::make('DS digest is empty');
        }

        return new self($keyTag, $algorithm, $digestType, $digest);
    }

    /**
     * Parse from the exact on-wire DS RDATA bytes.
     */
    public static function fromRdata(string $rdata): self
    {
        if (strlen($rdata) < 4) {
            throw MalformedRdata::make('DS RDATA shorter than 4 octets');
        }

        $keyTag = (ord($rdata[0]) << 8) | ord($rdata[1]);
        $algorithm = ord($rdata[2]);
        $digestType = ord($rdata[3]);
        $digest = substr($rdata, 4);

        if ($digest === '') {
            throw MalformedRdata::make('DS RDATA has empty digest');
        }

        return new self($keyTag, $algorithm, $digestType, $digest);
    }
}
