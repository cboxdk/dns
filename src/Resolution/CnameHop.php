<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolution;

/**
 * One link in a CNAME chain: an alias name and the canonical name it points at.
 */
readonly class CnameHop
{
    public function __construct(
        public string $from,
        public string $to,
    ) {}
}
