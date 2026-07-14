<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed HINFO record (RFC 1035 §3.3.2) — the host's CPU and OS strings. Now also
 * returned by some servers (RFC 8482) as a stock answer to an ANY query.
 */
readonly class Hinfo implements RecordData
{
    public function __construct(
        public string $cpu,
        public string $os,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::HINFO || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        $offset = 0;
        $cpu = self::charString($raw, $offset);
        $os = self::charString($raw, $offset);

        if ($cpu === null || $os === null) {
            return null;
        }

        return new self($cpu, $os);
    }

    public function presentation(): string
    {
        return "\"{$this->cpu}\" \"{$this->os}\"";
    }

    private static function charString(string $raw, int &$offset): ?string
    {
        if ($offset >= strlen($raw)) {
            return null;
        }

        $length = ord($raw[$offset]);
        $offset++;

        if ($offset + $length > strlen($raw)) {
            return null;
        }

        $value = substr($raw, $offset, $length);
        $offset += $length;

        return $value;
    }
}
