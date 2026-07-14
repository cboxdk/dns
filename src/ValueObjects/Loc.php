<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed LOC record (RFC 1876) — a geographic location. The wire form packs
 * latitude and longitude as offsets in thousandths of an arc-second and altitude in
 * centimetres, with size/precision fields log-encoded; this value object decodes
 * them into plain degrees and metres.
 *
 * `latitude` is positive north, `longitude` positive east; `altitude`, `size`,
 * `horizontalPrecision`, and `verticalPrecision` are in metres.
 */
readonly class Loc implements RecordData
{
    private const int ARC_DEGREE = 3_600_000; // thousandths of an arc-second per degree

    private const int ALTITUDE_BASE = 10_000_000; // centimetres of reference offset

    public function __construct(
        public float $latitude,
        public float $longitude,
        public float $altitude,
        public float $size,
        public float $horizontalPrecision,
        public float $verticalPrecision,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::LOC || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 16 || ord($raw[0]) !== 0) {
            return null; // wrong length or unsupported version
        }

        $latitude = (self::uint32($raw, 4) - 0x80000000) / self::ARC_DEGREE;
        $longitude = (self::uint32($raw, 8) - 0x80000000) / self::ARC_DEGREE;
        $altitude = (self::uint32($raw, 12) - self::ALTITUDE_BASE) / 100;

        return new self(
            $latitude,
            $longitude,
            $altitude,
            self::decodePrecision(ord($raw[1])),
            self::decodePrecision(ord($raw[2])),
            self::decodePrecision(ord($raw[3])),
        );
    }

    /**
     * The RFC 1876 §3 presentation, e.g. `42 21 54.000 N 71 06 18.000 W 24.00m 30.00m 10.00m 10.00m`.
     */
    public function presentation(): string
    {
        return sprintf(
            '%s %s %.2fm %.2fm %.2fm %.2fm',
            self::degreesToDms($this->latitude, 'N', 'S'),
            self::degreesToDms($this->longitude, 'E', 'W'),
            $this->altitude,
            $this->size,
            $this->horizontalPrecision,
            $this->verticalPrecision,
        );
    }

    private static function uint32(string $raw, int $offset): int
    {
        return (ord($raw[$offset]) << 24) | (ord($raw[$offset + 1]) << 16) | (ord($raw[$offset + 2]) << 8) | ord($raw[$offset + 3]);
    }

    /**
     * Decode a LOC size/precision octet: high nibble mantissa, low nibble base-10
     * exponent, giving a length in centimetres; returned in metres.
     */
    private static function decodePrecision(int $byte): float
    {
        $mantissa = ($byte >> 4) & 0x0F;
        $exponent = $byte & 0x0F;

        return $mantissa * (10 ** $exponent) / 100;
    }

    private static function degreesToDms(float $degrees, string $positive, string $negative): string
    {
        $hemisphere = $degrees >= 0 ? $positive : $negative;
        $value = abs($degrees);
        $d = (int) floor($value);
        $minutesFloat = ($value - $d) * 60;
        $m = (int) floor($minutesFloat);
        $seconds = ($minutesFloat - $m) * 60;

        return sprintf('%d %d %.3f %s', $d, $m, $seconds, $hemisphere);
    }
}
