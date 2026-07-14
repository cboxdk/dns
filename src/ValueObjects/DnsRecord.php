<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Enums\RecordType;

/**
 * A single resolved DNS record. `value` is the record's normalized RDATA as a
 * string (an IP for A/AAAA, the exchange host for MX, the joined text for TXT,
 * etc.); `priority` carries the MX/SRV preference when relevant. `raw` holds the
 * exact on-the-wire RDATA bytes — needed for DNSSEC canonical-form signature
 * reconstruction, where a decoded/normalized value would lose byte fidelity.
 */
final readonly class DnsRecord
{
    public function __construct(
        public RecordType $type,
        public string $name,
        public string $value,
        public int $ttl = 0,
        public ?int $priority = null,
        public ?string $raw = null,
    ) {}
}
