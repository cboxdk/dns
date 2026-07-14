<?php

declare(strict_types=1);

namespace Cbox\Dns\Testing;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * An in-memory {@see Resolver} for tests: stub the records a host+type resolves
 * to (optionally per nameserver, to model authoritative-vs-recursive differences)
 * without any network I/O.
 */
final class FakeResolver implements Resolver
{
    /** @var array<string, DnsResponse> */
    private array $stubs = [];

    /**
     * @param  list<string>  $values
     */
    public function stub(string $host, RecordType $type, array $values, ?string $nameserver = null, bool $authoritative = true): self
    {
        $records = array_map(
            static fn (string $value): DnsRecord => new DnsRecord($type, rtrim($host, '.'), $value, 300),
            $values,
        );

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
     * Stub a full {@see DnsResponse} — including raw DNSSEC records and an
     * authority section — for a host+type (optionally per nameserver). This is
     * the seam the DNSSEC chain-walk tests use to drive each zone level offline.
     */
    public function stubResponse(string $host, RecordType $type, DnsResponse $response, ?string $nameserver = null): self
    {
        $this->stubs[$this->key($host, $type, $nameserver)] = $response;

        return $this;
    }

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
    {
        return $this->stubs[$this->key($host, $type, $nameserver)]
            ?? $this->stubs[$this->key($host, $type, null)]
            ?? new DnsResponse($type, rtrim($host, '.'), [], $nameserver, ! $recursion);
    }

    private function key(string $host, RecordType $type, ?string $nameserver): string
    {
        return strtolower(rtrim($host, '.')).'|'.$type->value.'|'.($nameserver ?? '*');
    }
}
