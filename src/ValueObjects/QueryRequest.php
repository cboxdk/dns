<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\ConcurrentResolver;
use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;

/**
 * One query in a concurrent batch (see {@see ConcurrentResolver}): the same
 * parameters {@see Resolver::query()} takes, bundled so a list
 * of them can be dispatched together.
 */
readonly class QueryRequest
{
    public function __construct(
        public string $host,
        public RecordType $type,
        public ?string $nameserver = null,
        public bool $recursion = true,
        public bool $dnssec = false,
    ) {}
}
