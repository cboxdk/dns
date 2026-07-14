<?php

declare(strict_types=1);

namespace Cbox\Dns\Contracts;

use Cbox\Dns\Dnssec;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Resolves DNS records. Implementations decide the transport (raw socket, a
 * fake, …). `nameserver` targets a specific server — pass an authoritative
 * nameserver's IP with `recursion: false` to read the zone directly, bypassing
 * any recursive resolver's cache (the reliable path for ownership verification).
 *
 * `dnssec` requests the DNSSEC records (RRSIG/DNSKEY/DS/NSEC/NSEC3) by setting
 * the EDNS0 DO bit; transports that cannot carry them ignore it. DNSSEC trust
 * comes from validating those signatures ({@see Dnssec}), never from
 * trusting the transport, so a recursive DO query is a safe fetch path.
 */
interface Resolver
{
    public function query(
        string $host,
        RecordType $type,
        ?string $nameserver = null,
        bool $recursion = true,
        bool $dnssec = false,
    ): DnsResponse;
}
