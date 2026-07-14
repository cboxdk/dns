<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed CSYNC record (RFC 7477) — Child-to-parent synchronization: the SOA serial
 * the request is bound to, flags (immediate / soaminimum), and the set of record
 * types the parent should copy up from the child (e.g. NS, A, AAAA).
 */
readonly class Csync implements RecordData
{
    /**
     * @param  list<int>  $types  the wire TYPE codes named in the type bitmap
     */
    public function __construct(
        public int $serial,
        public int $flags,
        public array $types,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::CSYNC || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 6) {
            return null;
        }

        $serial = (ord($raw[0]) << 24) | (ord($raw[1]) << 16) | (ord($raw[2]) << 8) | ord($raw[3]);
        $flags = (ord($raw[4]) << 8) | ord($raw[5]);

        return new self($serial, $flags, self::typeBitmap(substr($raw, 6)));
    }

    /**
     * The type codes as their mnemonics where known (e.g. `NS`, `A`), or `TYPEn`.
     *
     * @return list<string>
     */
    public function typeNames(): array
    {
        return array_map(
            static function (int $code): string {
                $type = RecordType::fromCode($code);

                return $type === null ? "TYPE{$code}" : $type->value;
            },
            $this->types,
        );
    }

    public function presentation(): string
    {
        return trim("{$this->serial} {$this->flags} ".implode(' ', $this->typeNames()));
    }

    /**
     * Decode an NSEC-style type bitmap (RFC 4034 §4.1.2): a sequence of
     * `window(1) length(1) bitmap(length)` blocks.
     *
     * @return list<int>
     */
    private static function typeBitmap(string $bitmap): array
    {
        $types = [];
        $offset = 0;
        $length = strlen($bitmap);

        while ($offset + 2 <= $length) {
            $window = ord($bitmap[$offset]);
            $blockLength = ord($bitmap[$offset + 1]);
            $offset += 2;

            // RFC 4034 §4.1.2: a window bitmap block is at most 32 octets.
            if ($blockLength === 0 || $blockLength > 32 || $offset + $blockLength > $length) {
                break;
            }

            for ($i = 0; $i < $blockLength; $i++) {
                $byte = ord($bitmap[$offset + $i]);

                for ($bit = 0; $bit < 8; $bit++) {
                    if (($byte & (0x80 >> $bit)) !== 0) {
                        $types[] = $window * 256 + $i * 8 + $bit;
                    }
                }
            }

            $offset += $blockLength;
        }

        return $types;
    }
}
