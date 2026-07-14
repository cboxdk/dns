<?php

declare(strict_types=1);

namespace Cbox\Dns\Exceptions;

/**
 * The query could not be completed — the nameserver was unreachable, the socket
 * timed out, or no bytes came back. Distinct from a successful query that simply
 * returned no records.
 */
final class ResolutionFailed extends DnsException
{
    public static function make(string $nameserver, string $reason): self
    {
        return new self("DNS query to [{$nameserver}] failed: {$reason}.");
    }
}
