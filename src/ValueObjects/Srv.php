<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed SRV record (RFC 2782). The decoders keep the priority on
 * {@see DnsRecord::$priority} and render `weight port target` on
 * {@see DnsRecord::$value}; {@see self::fromRecord()} reassembles the four fields.
 */
readonly class Srv implements RecordData
{
    public function __construct(
        public int $priority,
        public int $weight,
        public int $port,
        public string $target,
    ) {}

    /**
     * Build from an SRV {@see DnsRecord}, or null if it is not an SRV record or its
     * value is not the expected `weight port target` form.
     */
    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::SRV) {
            return null;
        }

        $parts = preg_split('/\s+/', trim($record->value)) ?: [];

        if (count($parts) < 3 || ! ctype_digit($parts[0]) || ! ctype_digit($parts[1])) {
            return null;
        }

        return new self(
            $record->priority ?? 0,
            (int) $parts[0],
            (int) $parts[1],
            rtrim($parts[2], '.'),
        );
    }

    public function presentation(): string
    {
        return "{$this->priority} {$this->weight} {$this->port} {$this->target}";
    }
}
