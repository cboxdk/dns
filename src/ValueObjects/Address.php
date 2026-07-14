<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;

/**
 * A parsed A / AAAA record — an IP address, with a flag for which family.
 */
readonly class Address implements RecordData
{
    public function __construct(
        public string $ip,
        public bool $ipv6,
    ) {}

    public function presentation(): string
    {
        return $this->ip;
    }
}
