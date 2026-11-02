<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * A zone's `_domainconnect` record points somewhere we will not fetch from: a
 * scheme other than https, a malformed value, or a host on a non-public address.
 */
class DiscoveryRefused extends DnsException
{
    public static function because(string $apex, string $reason): self
    {
        return new self("Refused Domain Connect discovery for [{$apex}]: {$reason}.");
    }
}
