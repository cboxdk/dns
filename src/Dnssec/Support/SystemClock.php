<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Support;

use Cbox\Dns\Dnssec\Contracts\Clock;

/**
 * The production {@see Clock}: wall-clock time from the host.
 */
final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}
