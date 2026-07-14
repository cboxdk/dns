<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Contracts;

/**
 * The source of "now" for RRSIG validity-window checks. Injectable so tests pin
 * time deterministically against a captured signature's inception/expiration
 * (a real signature is only valid inside a fixed window), and so an operator can
 * substitute a trusted clock.
 */
interface Clock
{
    /**
     * The current time as a Unix timestamp (seconds since the epoch, UTC).
     */
    public function now(): int;
}
