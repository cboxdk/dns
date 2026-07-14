<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;

/**
 * A parsed SOA record (RFC 1035 §3.3.13). The socket/DoH decoders render an SOA as
 * a seven-field presentation string on {@see DnsRecord::$value}; this value object
 * turns that back into typed fields so callers (and the SOA diagnostics check)
 * don't each re-implement the split.
 */
readonly class Soa implements RecordData
{
    public function __construct(
        public string $mname,
        public string $rname,
        public int $serial,
        public int $refresh,
        public int $retry,
        public int $expire,
        public int $minimum,
    ) {}

    /**
     * Parse the seven-field presentation form
     * (`mname rname serial refresh retry expire minimum`), or null if it is not
     * well-formed.
     */
    public static function fromPresentation(string $value): ?self
    {
        $parts = preg_split('/\s+/', trim($value)) ?: [];

        if (count($parts) < 7) {
            return null;
        }

        foreach ([2, 3, 4, 5, 6] as $index) {
            if (! ctype_digit($parts[$index])) {
                return null;
            }
        }

        return new self(
            $parts[0],
            $parts[1],
            (int) $parts[2],
            (int) $parts[3],
            (int) $parts[4],
            (int) $parts[5],
            (int) $parts[6],
        );
    }

    public function presentation(): string
    {
        return "{$this->mname} {$this->rname} {$this->serial} {$this->refresh} {$this->retry} {$this->expire} {$this->minimum}";
    }
}
