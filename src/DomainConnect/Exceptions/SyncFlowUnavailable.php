<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * The synchronous flow cannot be used: the DNS provider publishes no
 * `urlSyncUX`, or the template sets `syncBlock`.
 */
class SyncFlowUnavailable extends DnsException
{
    public static function because(string $reason): self
    {
        return new self("The Domain Connect synchronous flow is unavailable: {$reason}.");
    }
}
