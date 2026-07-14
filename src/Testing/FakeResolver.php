<?php

declare(strict_types=1);

namespace Cbox\Dns\Testing;

use Cbox\Dns\Contracts\ConcurrentResolver;
use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\QueryRequest;
use RuntimeException;

/**
 * An in-memory {@see Resolver} for tests: stub the records a host+type resolves
 * to (optionally per nameserver, to model authoritative-vs-recursive differences)
 * without any network I/O. It also records every query so a test can assert what
 * was asked, and implements {@see ConcurrentResolver} so the concurrent propagation
 * path is exercised deterministically offline.
 */
class FakeResolver implements ConcurrentResolver, Resolver
{
    /** @var array<string, DnsResponse> */
    private array $stubs = [];

    /** @var list<QueryRequest> */
    private array $queries = [];

    private bool $strict = false;

    /**
     * Stub the string values a host+type resolves to. `ttl` and `priority` let a
     * fixture model a low-TTL record or an MX/SRV preference; for records that need
     * per-record priorities, use {@see self::stubRecords()}.
     *
     * @param  list<string>  $values
     */
    public function stub(string $host, RecordType $type, array $values, ?string $nameserver = null, bool $authoritative = true, int $ttl = 300, ?int $priority = null): self
    {
        $records = array_map(
            static fn (string $value): DnsRecord => new DnsRecord($type, rtrim($host, '.'), $value, $ttl, $priority),
            $values,
        );

        return $this->stubRecords($host, $type, $records, $nameserver, $authoritative);
    }

    /**
     * Stub fully-formed records (per-record TTL/priority/raw) for a host+type.
     *
     * @param  list<DnsRecord>  $records
     */
    public function stubRecords(string $host, RecordType $type, array $records, ?string $nameserver = null, bool $authoritative = true): self
    {
        $this->stubs[$this->key($host, $type, $nameserver)] = new DnsResponse(
            $type,
            rtrim($host, '.'),
            $records,
            $nameserver,
            $authoritative,
        );

        return $this;
    }

    /**
     * Stub a query that fails with a non-NoError response code (SERVFAIL, NXDOMAIN,
     * …) — so a test can drive the RCODE-dependent paths a bare empty answer cannot.
     */
    public function stubFailure(string $host, RecordType $type, Rcode $rcode = Rcode::ServFail, ?string $nameserver = null): self
    {
        $this->stubs[$this->key($host, $type, $nameserver)] = new DnsResponse(
            $type,
            rtrim($host, '.'),
            [],
            $nameserver,
            rcode: $rcode,
        );

        return $this;
    }

    /**
     * Stub a full {@see DnsResponse} — including raw DNSSEC records and an
     * authority section — for a host+type (optionally per nameserver). This is
     * the seam the DNSSEC chain-walk tests use to drive each zone level offline.
     */
    public function stubResponse(string $host, RecordType $type, DnsResponse $response, ?string $nameserver = null): self
    {
        $this->stubs[$this->key($host, $type, $nameserver)] = $response;

        return $this;
    }

    /**
     * In strict mode an unstubbed query throws instead of returning an empty
     * answer, so a fixture typo surfaces as a failure rather than a silent miss.
     */
    public function strict(bool $strict = true): self
    {
        $this->strict = $strict;

        return $this;
    }

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
    {
        $this->queries[] = new QueryRequest($host, $type, $nameserver, $recursion, $dnssec);

        $stub = $this->stubs[$this->key($host, $type, $nameserver)]
            ?? $this->stubs[$this->key($host, $type, null)]
            ?? null;

        if ($stub !== null) {
            return $stub;
        }

        if ($this->strict) {
            throw ResolutionFailed::make($nameserver ?? '(recursive)', "no stub for {$host} {$type->value}");
        }

        return new DnsResponse($type, rtrim($host, '.'), [], $nameserver, ! $recursion);
    }

    /**
     * @param  list<QueryRequest>  $requests
     * @return list<DnsResponse>
     */
    public function queryConcurrently(array $requests): array
    {
        return array_map(
            fn (QueryRequest $r): DnsResponse => $this->query($r->host, $r->type, $r->nameserver, $r->recursion, $r->dnssec),
            $requests,
        );
    }

    /**
     * Every query this fake received, in order.
     *
     * @return list<QueryRequest>
     */
    public function queries(): array
    {
        return $this->queries;
    }

    /**
     * Assert a matching query was made (a null `$nameserver` matches any server).
     *
     * @throws RuntimeException when no recorded query matches
     */
    public function assertQueried(string $host, RecordType $type, ?string $nameserver = null): void
    {
        $host = strtolower(rtrim($host, '.'));

        foreach ($this->queries as $query) {
            if (strtolower(rtrim($query->host, '.')) === $host
                && $query->type === $type
                && ($nameserver === null || $query->nameserver === $nameserver)) {
                return;
            }
        }

        throw new RuntimeException("Expected a query for {$host} {$type->value}".($nameserver !== null ? " at {$nameserver}" : '').', but none was recorded.');
    }

    private function key(string $host, RecordType $type, ?string $nameserver): string
    {
        return strtolower(rtrim($host, '.')).'|'.$type->value.'|'.($nameserver ?? '*');
    }
}
