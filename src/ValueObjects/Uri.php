<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed URI record (RFC 7553) — maps a name to a URI, with a priority and weight
 * for selecting among alternatives (lower priority first, as with SRV/MX).
 */
readonly class Uri implements RecordData
{
    public function __construct(
        public int $priority,
        public int $weight,
        public string $target,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::URI || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 4) {
            return null;
        }

        $priority = (ord($raw[0]) << 8) | ord($raw[1]);
        $weight = (ord($raw[2]) << 8) | ord($raw[3]);

        return new self($priority, $weight, substr($raw, 4));
    }

    public function presentation(): string
    {
        return "{$this->priority} {$this->weight} \"{$this->target}\"";
    }
}
