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
     * @param  list<DnsRecord>  $records  the answer records of the queried type
     * @param  list<DnsRecord>  $answer  every recognised answer-section record
     *                                   (the queried type plus its RRSIGs, …)
     * @param  list<DnsRecord>  $authority  every recognised authority-section
     *                                      record — where NSEC/NSEC3 denial-of-
     *                                      existence proofs and their RRSIGs live
     */
    public function __construct(
        public RecordType $type,
        public string $host,
        public array $records,
        public ?string $nameserver = null,
        public bool $authoritative = false,
        public bool $authenticated = false,
        public array $answer = [],
        public array $authority = [],
    ) {}

    /**
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (DnsRecord $r): string => $r->value, $this->records);
    }

    /**
     * The answer-section records of a given type — used to pull the RRSIG(s) that
     * cover an RRset out of the same response.
     *
     * @return list<DnsRecord>
     */
    public function answerOfType(RecordType $type): array
    {
        return array_values(array_filter(
            $this->answer,
            static fn (DnsRecord $r): bool => $r->type === $type,
        ));
    }

    /**
     * The authority-section records of a given type.
     *
     * @return list<DnsRecord>
     */
    public function authorityOfType(RecordType $type): array
    {
        return array_values(array_filter(
            $this->authority,
            static fn (DnsRecord $r): bool => $r->type === $type,
        ));
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
