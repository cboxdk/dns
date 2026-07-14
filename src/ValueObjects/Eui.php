<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed EUI48 / EUI64 record (RFC 7043) — a 48- or 64-bit IEEE hardware address
 * (a MAC address) published in DNS, in the canonical hyphen-separated hex form.
 */
readonly class Eui implements RecordData
{
    public function __construct(
        public string $address,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if (($record->type !== RecordType::EUI48 && $record->type !== RecordType::EUI64) || $record->raw === null) {
            return null;
        }

        $size = $record->type === RecordType::EUI48 ? 6 : 8;

        return self::fromRdata($record->raw, $size);
    }

    public static function fromRdata(string $raw, int $size): ?self
    {
        if (strlen($raw) !== $size) {
            return null;
        }

        return new self(implode('-', str_split(bin2hex($raw), 2)));
    }

    public function presentation(): string
    {
        return $this->address;
    }
}
