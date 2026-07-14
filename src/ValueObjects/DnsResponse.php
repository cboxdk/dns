<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Enums\RecordType;

/**
 * The answer to one DNS query: the records returned, which nameserver answered,
 * and whether that answer was authoritative (the AA bit / a direct authoritative
 * query) — the distinction that matters for ownership verification, where a
 * recursive resolver's cached view must never be trusted.
 *
 * `authenticated` carries the DNSSEC-validated signal (the AD bit) when the
 * transport reports it — DoH JSON exposes it directly. It is advisory only:
 * this package does not itself validate the DNSSEC chain (that lives in the
 * dedicated `Cbox\Dns\Dnssec` module), so never treat a bare `true` here as a
 * substitute for chain validation.
 */
final readonly class DnsResponse
{
    /**
     * @param  list<DnsRecord>  $records
     */
    public function __construct(
        public RecordType $type,
        public string $host,
        public array $records,
        public ?string $nameserver = null,
        public bool $authoritative = false,
        public bool $authenticated = false,
    ) {}

    /**
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (DnsRecord $r): string => $r->value, $this->records);
    }

    public function contains(string $value): bool
    {
        return in_array($value, $this->values(), true);
    }

    public function isEmpty(): bool
    {
        return $this->records === [];
    }
}
