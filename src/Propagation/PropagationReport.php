<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

/**
 * The result of a propagation check: the authoritative record set, each public
 * resolver's view of it, and an overall {@see PropagationStatus}.
 */
final readonly class PropagationReport
{
    /**
     * @param  list<string>  $authoritativeValues
     * @param  list<ResolverResult>  $results
     */
    public function __construct(
        public array $authoritativeValues,
        public array $results,
        public PropagationStatus $status,
    ) {}

    /**
     * The public resolvers whose view has not yet caught up with the authoritative set.
     *
     * @return list<ResolverResult>
     */
    public function stale(): array
    {
        return array_values(array_filter($this->results, static fn (ResolverResult $r): bool => ! $r->agrees));
    }
}
