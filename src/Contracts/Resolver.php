<?php

declare(strict_types=1);

namespace Cbox\Dns\Contracts;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Resolves DNS records. Implementations decide the transport (raw socket, a
 * fake, …). `nameserver` targets a specific server — pass an authoritative
 * nameserver's IP with `recursion: false` to read the zone directly, bypassing
 * any recursive resolver's cache (the reliable path for ownership verification).
 */
interface Resolver
{
    public function query(
        string $host,
        RecordType $type,
        ?string $nameserver = null,
        bool $recursion = true,
    ): DnsResponse;
}
