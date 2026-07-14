<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed MX record — the mail exchange host and its preference (lower is
 * preferred, RFC 5321 §5.1).
 */
readonly class Mx implements RecordData
{
    public function __construct(
        public int $preference,
        public string $exchange,
    ) {}

    /**
     * Build from an MX {@see DnsRecord}, or null if it is the wrong type.
     */
    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::MX) {
            return null;
        }

        return new self($record->priority ?? 0, rtrim($record->value, '.'));
    }

    public function presentation(): string
    {
        return "{$this->preference} {$this->exchange}";
    }
}
