<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed NAPTR record (RFC 3403) — the regex-rewrite rule used by ENUM/SIP and
 * other dynamic delegation discovery. Fields: order and preference (lower first),
 * the flags, the service, the substitution regexp, and the replacement name.
 */
readonly class Naptr implements RecordData
{
    public function __construct(
        public int $order,
        public int $preference,
        public string $flags,
        public string $service,
        public string $regexp,
        public string $replacement,
    ) {}

    /**
     * Build from a NAPTR {@see DnsRecord} using its raw wire RDATA, or null if it is
     * the wrong type or carries no raw bytes.
     */
    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::NAPTR || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    /**
     * Parse NAPTR wire RDATA (order, preference, three character-strings, then the
     * uncompressed replacement name), or null if it is malformed.
     */
    public static function fromRdata(string $raw): ?self
    {
        $length = strlen($raw);

        if ($length < 4) {
            return null;
        }

        $order = (ord($raw[0]) << 8) | ord($raw[1]);
        $preference = (ord($raw[2]) << 8) | ord($raw[3]);
        $offset = 4;

        $strings = [];
        for ($i = 0; $i < 3; $i++) {
            if ($offset >= $length) {
                return null;
            }

            $itemLength = ord($raw[$offset]);
            $offset++;

            if ($offset + $itemLength > $length) {
                return null;
            }

            $strings[] = substr($raw, $offset, $itemLength);
            $offset += $itemLength;
        }

        $labels = [];
        while ($offset < $length) {
            $labelLength = ord($raw[$offset]);
            $offset++;

            if ($labelLength === 0) {
                break;
            }

            if (($labelLength & 0xC0) === 0xC0 || $offset + $labelLength > $length) {
                return null;
            }

            $labels[] = substr($raw, $offset, $labelLength);
            $offset += $labelLength;
        }

        return new self(
            $order,
            $preference,
            $strings[0],
            $strings[1],
            $strings[2],
            $labels === [] ? '.' : implode('.', $labels),
        );
    }

    public function presentation(): string
    {
        return "{$this->order} {$this->preference} \"{$this->flags}\" \"{$this->service}\" \"{$this->regexp}\" {$this->replacement}";
    }
}
