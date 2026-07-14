<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;

/**
 * A parsed record whose RDATA is a single domain name — CNAME, NS, or PTR.
 */
readonly class Name implements RecordData
{
    public function __construct(
        public string $name,
    ) {}

    public function presentation(): string
    {
        return $this->name;
    }
}
