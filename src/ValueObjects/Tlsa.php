<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed TLSA record (RFC 6698) — the DANE association that pins a certificate or
 * public key for a service. The four fields are the certificate usage, the selector
 * (full cert vs. SubjectPublicKeyInfo), the matching type (exact / SHA-256 /
 * SHA-512), and the association data.
 */
readonly class Tlsa implements RecordData
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

    /**
     * Build from a TLSA {@see DnsRecord} using its raw wire RDATA, or null if it is
     * the wrong type or carries no raw bytes.
     */
    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::TLSA || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    /**
     * Parse TLSA wire RDATA (usage, selector, matching-type, then association data),
     * or null if it is too short.
     */
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
