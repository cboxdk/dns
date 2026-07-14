<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed CDS record (RFC 7344) — a Child DS: the DS a zone wants its parent to
 * publish, for automated DNSSEC delegation maintenance. Same fields as DS.
 */
readonly class Cds implements RecordData
{
    /**
     * @param  string  $digest  the digest as lowercase hex
     */
    public function __construct(
        public int $keyTag,
        public int $algorithm,
        public int $digestType,
        public string $digest,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::CDS || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 4) {
            return null;
        }

        $keyTag = (ord($raw[0]) << 8) | ord($raw[1]);

        return new self($keyTag, ord($raw[2]), ord($raw[3]), bin2hex(substr($raw, 4)));
    }

    public function presentation(): string
    {
        return "{$this->keyTag} {$this->algorithm} {$this->digestType} {$this->digest}";
    }
}
