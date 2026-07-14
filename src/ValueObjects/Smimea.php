<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed SMIMEA record (RFC 8162) — an S/MIME certificate association, wire-format
 * identical to TLSA but bound to an email identity rather than a TLS service: the
 * certificate usage, the selector, the matching type, and the association data.
 */
readonly class Smimea implements RecordData
{
    /**
     * @param  string  $association  the association data as lowercase hex
     */
    public function __construct(
        public int $certificateUsage,
        public int $selector,
        public int $matchingType,
        public string $association,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::SMIMEA || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 3) {
            return null;
        }

        return new self(ord($raw[0]), ord($raw[1]), ord($raw[2]), bin2hex(substr($raw, 3)));
    }

    public function presentation(): string
    {
        return "{$this->certificateUsage} {$this->selector} {$this->matchingType} {$this->association}";
    }
}
