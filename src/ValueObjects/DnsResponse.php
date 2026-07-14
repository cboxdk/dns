<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;

/**
 * The answer to one DNS query: the records returned, which nameserver answered,
 * and whether that answer was authoritative (the AA bit / a direct authoritative
 * query) — the distinction that matters for ownership verification, where a
 * recursive resolver's cached view must never be trusted.
 *
 * `rcode` is the response code (RFC 1035 §4.1.1). It is what lets a caller tell a
 * name that does not exist (`NxDomain`) from a name that exists with no record of
 * this type (`NoError` + empty `records`) from a broken server (`ServFail`) — a
 * distinction a bare "empty answer" would erase.
 *
 * `authenticated` carries the DNSSEC-validated signal (the AD bit) when the
 * transport reports it — DoH JSON exposes it directly. It is advisory only:
 * this package does not itself validate the DNSSEC chain (that lives in the
 * dedicated `Cbox\Dns\Dnssec` module), so never treat a bare `true` here as a
 * substitute for chain validation.
 */
readonly class DnsResponse
{
    /**
     * @param  list<DnsRecord>  $records  the answer records of the queried type
     * @param  list<DnsRecord>  $answer  every recognised answer-section record
     *                                   (the queried type plus its RRSIGs, …)
     * @param  list<DnsRecord>  $authority  every recognised authority-section
     *                                      record — where NSEC/NSEC3 denial-of-
     *                                      existence proofs and their RRSIGs live
     * @param  list<DnsRecord>  $additional  every recognised additional-section
     *                                       record — glue (A/AAAA of the referral
     *                                       nameservers) lives here
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
        public Rcode $rcode = Rcode::NoError,
        public array $additional = [],
    ) {}

    /**
     * Whether the server answered without an error code (RCODE 0). A `true` here
     * with an empty {@see self::$records} is a genuine NODATA (the name exists, but
     * not for this type); `false` means the query itself failed at the server.
     */
    public function succeeded(): bool
    {
        return $this->rcode === Rcode::NoError;
    }

    /**
     * The queried name provably does not exist (RCODE 3, NXDOMAIN).
     */
    public function isNxDomain(): bool
    {
        return $this->rcode === Rcode::NxDomain;
    }

    /**
     * The server failed to answer (RCODE 2, SERVFAIL) — a transient/broken-server
     * signal, distinct from a name that simply has no such record.
     */
    public function isServFail(): bool
    {
        return $this->rcode === Rcode::ServFail;
    }

    /**
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (DnsRecord $r): string => $r->value, $this->records);
    }

    /**
     * The typed value objects for the answer records — `Address`, `Mx`, `Svcb`, …
     * Records with no general-purpose object (the DNSSEC types) are omitted.
     *
     * @return list<RecordData>
     */
    public function data(): array
    {
        return array_values(array_filter(
            array_map(static fn (DnsRecord $r): ?RecordData => $r->data(), $this->records),
        ));
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

    /**
     * The additional-section records of a given type (e.g. glue A/AAAA records).
     *
     * @return list<DnsRecord>
     */
    public function additionalOfType(RecordType $type): array
    {
        return array_values(array_filter(
            $this->additional,
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
