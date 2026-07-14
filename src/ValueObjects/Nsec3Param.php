<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed NSEC3PARAM record (RFC 5155 §4) — the hash algorithm, flags, iteration
 * count, and salt a zone uses to generate its NSEC3 chain.
 */
readonly class Nsec3Param implements RecordData
{
    /**
     * @param  ?string  $salt  the salt as lowercase hex, or null for the empty salt
     */
    public function __construct(
        public int $hashAlgorithm,
        public int $flags,
        public int $iterations,
        public ?string $salt,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::NSEC3PARAM || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 5) {
            return null;
        }

        $iterations = (ord($raw[2]) << 8) | ord($raw[3]);
        $saltLength = ord($raw[4]);

        if (5 + $saltLength > strlen($raw)) {
            return null;
        }

        $salt = $saltLength === 0 ? null : bin2hex(substr($raw, 5, $saltLength));

        return new self(ord($raw[0]), ord($raw[1]), $iterations, $salt);
    }

    public function presentation(): string
    {
        return "{$this->hashAlgorithm} {$this->flags} {$this->iterations} ".($this->salt ?? '-');
    }
}
