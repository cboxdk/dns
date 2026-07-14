<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

/**
 * A named public recursive resolver in the propagation registry: a stable machine
 * `name` (e.g. `google-primary`), a human `label` (e.g. "Google Public DNS"), the
 * `ip` to query, and an optional `region` note.
 *
 * The `region` is the operator's stated location or "Global (anycast)" — it is NOT
 * a geographic vantage point. Querying `8.8.8.8` from this host still exits through
 * the machine's own uplink and lands on the nearest anycast PoP, so `region` is a
 * label for the operator, not proof of where the lookup was answered. See
 * {@see PropagationChecker} for the honest scope of a multi-provider check.
 */
final readonly class PublicResolver
{
    public function __construct(
        public string $name,
        public string $label,
        public string $ip,
        public ?string $region = null,
    ) {}
}
