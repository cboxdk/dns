<?php

declare(strict_types=1);

namespace Cbox\Dns\Contracts;

use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * The typed, parsed RDATA of a DNS record. Every record type this library
 * understands has a value object implementing this contract, reachable via
 * {@see DnsRecord::data()} — so a consumer works with `->port`, `->exchange`,
 * `->alpn`, `->serial` and friends rather than parsing a presentation string or
 * touching raw wire bytes.
 */
interface RecordData
{
    /**
     * The canonical presentation form of the record (what `dig` prints).
     */
    public function presentation(): string;
}
