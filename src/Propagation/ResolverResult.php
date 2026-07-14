<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

/**
 * One public resolver's view during a propagation check: which nameserver was
 * asked, the provider's human `label` (null for a bare, unnamed IP panel), the
 * values it returned, and whether that set matches the authoritative one.
 */
readonly class ResolverResult
{
    /**
     * @param  list<string>  $values
     */
    public function __construct(
        public string $nameserver,
        public array $values,
        public bool $agrees,
        public ?string $label = null,
    ) {}
}
