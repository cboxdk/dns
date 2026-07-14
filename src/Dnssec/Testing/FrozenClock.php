<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Testing;

use Cbox\Dns\Dnssec\Contracts\Clock;

/**
 * A {@see Clock} pinned to a fixed instant, for tests that verify a captured
 * RRSIG against its real (immutable) validity window, or that exercise the
 * expired / not-yet-valid rejection paths deterministically.
 */
class FrozenClock implements Clock
{
    public function __construct(private readonly int $timestamp) {}

    public function now(): int
    {
        return $this->timestamp;
    }
}
