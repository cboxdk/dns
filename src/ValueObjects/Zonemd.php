<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed ZONEMD record (RFC 8976) — a cryptographic digest of the whole zone, so
 * a recipient can verify a zone's integrity: the SOA serial it covers, the scheme,
 * the hash algorithm, and the digest.
 */
readonly class Zonemd implements RecordData
{
    /**
     * @param  string  $digest  the digest as lowercase hex
     */
    public function __construct(
        public int $serial,
        public int $scheme,
        public int $hashAlgorithm,
        public string $digest,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::ZONEMD || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 6) {
            return null;
        }

        $serial = (ord($raw[0]) << 24) | (ord($raw[1]) << 16) | (ord($raw[2]) << 8) | ord($raw[3]);

        return new self($serial, ord($raw[4]), ord($raw[5]), bin2hex(substr($raw, 6)));
    }

    public function presentation(): string
    {
        return "{$this->serial} {$this->scheme} {$this->hashAlgorithm} {$this->digest}";
    }
}
