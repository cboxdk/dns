<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

/**
 * What to apply where: a template, the zone (apex + host), the values for the
 * template's variables, and optionally which groups, where to send the user
 * back to, and an opaque state echoed on that redirect.
 */
readonly class ApplyRequest
{
    /**
     * @param  array<string, string>  $variables
     * @param  list<string>  $groupIds
     */
    public function __construct(
        public Template $template,
        public Zone $zone,
        public array $variables,
        public array $groupIds = [],
        public ?string $redirectUri = null,
        public ?string $state = null,
    ) {}
}
