<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed CDNSKEY record (RFC 7344) — a Child DNSKEY: the key a zone wants its
 * parent to build a DS from, for automated DNSSEC delegation maintenance. Same
 * fields as DNSKEY.
 */
readonly class Cdnskey implements RecordData
{
    /**
     * @param  string  $publicKey  the public key, base64-encoded
     */
    public function __construct(
        public int $flags,
        public int $protocol,
        public int $algorithm,
        public string $publicKey,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::CDNSKEY || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 4) {
            return null;
        }

        $flags = (ord($raw[0]) << 8) | ord($raw[1]);

        return new self($flags, ord($raw[2]), ord($raw[3]), base64_encode(substr($raw, 4)));
    }

    public function presentation(): string
    {
        return "{$this->flags} {$this->protocol} {$this->algorithm} {$this->publicKey}";
    }
}
