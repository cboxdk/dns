<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\Diagnostics\Report;
use Cbox\Dns\Dns;

/**
 * The Domain Connect front door: discover, build the apply URL, expand a template
 * into the records it should produce, check them against authoritative DNS, and
 * read the provider's redirect back. Reach it through {@see Dns::domainConnect()}.
 */
class DomainConnect
{
    public function __construct(
        private readonly Discoverer $discoverer,
        private readonly SyncUrlBuilder $urls,
        private readonly Resolver $resolver,
    ) {}

    public function discover(string $name, ?Template $template = null): Discovery
    {
        return $this->discoverer->discover($name, $template);
    }

    public function applyUrl(ApplyRequest $request, ProviderSettings $settings): string
    {
        return $this->urls->build($request, $settings);
    }

    /**
     * @param  array<string, string>  $variables
     * @param  list<string>  $groupIds
     */
    public function recordSet(Template $template, Zone $zone, array $variables, array $groupIds = []): RecordSet
    {
        return RecordSet::fromTemplate($template, $zone, $variables, $groupIds);
    }

    public function check(RecordSet $set): Report
    {
        return (new Diagnostics($this->resolver))->runWith($set->zone->apex, [new RecordSetCheck($set)]);
    }

    /**
     * @param  array<string, mixed>  $query  the provider's redirect query string, parsed
     */
    public function outcome(array $query): ApplyOutcome
    {
        return ApplyOutcome::fromQuery($query);
    }
}
