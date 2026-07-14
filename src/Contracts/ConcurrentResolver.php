<?php

declare(strict_types=1);

namespace Cbox\Dns\Contracts;

use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\QueryRequest;

/**
 * An optional capability a {@see Resolver} MAY also implement: resolve a batch of
 * independent queries concurrently, so polling N nameservers costs one timeout
 * budget rather than N sequential ones (the propagation panel is the motivating
 * case). Callers should feature-detect with `instanceof` and fall back to
 * sequential {@see Resolver::query()} when it is absent.
 *
 * The returned list is aligned to the input by index; a probe that fails or times
 * out is represented by an empty {@see DnsResponse} (no records, a failure rcode)
 * rather than throwing, so every slot can be read uniformly.
 */
interface ConcurrentResolver
{
    /**
     * @param  list<QueryRequest>  $requests
     * @return list<DnsResponse>
     */
    public function queryConcurrently(array $requests): array;
}
