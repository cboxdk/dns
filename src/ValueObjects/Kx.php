<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Support\RawName;

/**
 * A parsed KX record (RFC 2230) — a Key Exchange delegation: a preference (lower
 * first, like MX) and the name of a host willing to act as a key-exchange proxy.
 */
readonly class Kx implements RecordData
{
    public function __construct(
        public int $preference,
        public string $exchanger,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::KX || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 3) {
            return null;
        }

        $preference = (ord($raw[0]) << 8) | ord($raw[1]);
        $offset = 2;
        $exchanger = RawName::read($raw, $offset);

        if ($exchanger === null) {
            return null;
        }

        return new self($preference, $exchanger);
    }

    public function presentation(): string
    {
        return "{$this->preference} {$this->exchanger}";
    }
}
