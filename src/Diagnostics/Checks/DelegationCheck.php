<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Checks the delegation of the zone: the NS set the parent hands out (seen via a
 * recursive resolver) should match the NS set the zone serves for itself (read
 * authoritatively), and every in-bailiwick nameserver — one whose name lives inside
 * the zone — needs glue (an address record) at the parent, or resolution deadlocks.
 *
 * A parent/zone NS mismatch is a Warning, not an error, because it resolves as soon
 * as the slower side's TTL expires; missing glue for an in-zone NS is a Warning
 * because it can break bootstrap resolution.
 */
final class DelegationCheck implements Check
{
    private const string CATEGORY = 'Delegation';

    public function run(DiagnosticContext $ctx): array
    {
        $parent = $this->normalise($ctx->nameservers());
        $zone = $this->normalise($this->zoneNameservers($ctx));

        if ($parent === [] && $zone === []) {
            return [Finding::error(self::CATEGORY, 'delegation.ns', 'The zone has no NS records at the parent or authoritatively.')];
        }

        $findings = [$parent === $zone
            ? Finding::info(self::CATEGORY, 'delegation.match', 'The parent and zone NS sets agree.', ['ns' => $zone])
            : Finding::warning(
                self::CATEGORY,
                'delegation.match',
                'The parent delegation NS set does not match the NS set the zone serves for itself.',
                ['parent' => $parent, 'zone' => $zone],
            )];

        foreach ($this->checkGlue($ctx, $zone === [] ? $parent : $zone) as $finding) {
            $findings[] = $finding;
        }

        return $findings;
    }

    /**
     * @param  list<string>  $nameservers
     * @return list<Finding>
     */
    private function checkGlue(DiagnosticContext $ctx, array $nameservers): array
    {
        $findings = [];

        foreach ($nameservers as $nameserver) {
            // Glue is only required for in-bailiwick nameservers (name inside the
            // zone); an out-of-zone NS is resolved through its own zone, no glue.
            if (! $this->inBailiwick($nameserver, $ctx->domain)) {
                continue;
            }

            if ($ctx->addresses($nameserver) === []) {
                $findings[] = Finding::warning(
                    self::CATEGORY,
                    'delegation.glue',
                    "In-zone nameserver {$nameserver} has no glue (address) record — resolution can deadlock.",
                    ['nameserver' => $nameserver],
                );
            }
        }

        if ($findings === []) {
            $findings[] = Finding::info(self::CATEGORY, 'delegation.glue', 'Glue is present for every in-zone nameserver.');
        }

        return $findings;
    }

    /**
     * @return list<string>
     */
    private function zoneNameservers(DiagnosticContext $ctx): array
    {
        try {
            return $ctx->authoritative->query($ctx->domain, RecordType::NS, $ctx->domain)->values();
        } catch (DnsException) {
            return [];
        }
    }

    private function inBailiwick(string $nameserver, string $domain): bool
    {
        return $nameserver === $domain || str_ends_with($nameserver, '.'.$domain);
    }

    /**
     * @param  list<string>  $names
     * @return list<string>
     */
    private function normalise(array $names): array
    {
        $unique = array_values(array_unique(array_map(
            static fn (string $name): string => strtolower(rtrim($name, '.')),
            $names,
        )));

        sort($unique);

        return $unique;
    }
}
