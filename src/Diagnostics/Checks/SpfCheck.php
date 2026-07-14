<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Inspects the domain's SPF policy (a `v=spf1` TXT at the apex): warns when it is
 * missing or duplicated (RFC 7208 requires exactly one), when the DNS-lookup
 * mechanism budget is exceeded, and when it ends in a permissive `+all`.
 *
 * The lookup budget is a STATIC count of lookup-causing mechanisms in this one
 * record (`include`, `a`, `mx`, `ptr`, `exists`, and the `redirect` modifier); it
 * does not recurse into included policies, which would need live resolution of
 * every `include:` target. That recursion is a documented roadmap item.
 */
final class SpfCheck implements Check
{
    private const string CATEGORY = 'Email';

    private const int MAX_LOOKUPS = 10;

    private const array LOOKUP_MECHANISMS = ['include', 'a', 'mx', 'ptr', 'exists'];

    public function run(DiagnosticContext $ctx): array
    {
        try {
            $records = $ctx->resolver->query($ctx->domain, RecordType::TXT)->values();
        } catch (DnsException) {
            $records = [];
        }

        $spf = array_values(array_filter(
            $records,
            static fn (string $txt): bool => stripos(ltrim($txt), 'v=spf1') === 0,
        ));

        if ($spf === []) {
            return [Finding::warning(
                self::CATEGORY,
                'spf.presence',
                'No SPF record (v=spf1 TXT) at the apex — senders cannot be authorised.',
            )];
        }

        if (count($spf) > 1) {
            return [Finding::warning(
                self::CATEGORY,
                'spf.presence',
                'Multiple SPF records published — RFC 7208 requires exactly one; receivers will treat this as a permerror.',
                ['records' => $spf],
            )];
        }

        $record = $spf[0];
        $findings = [];

        $lookups = $this->lookupCount($record);

        if ($lookups > self::MAX_LOOKUPS) {
            $findings[] = Finding::error(
                self::CATEGORY,
                'spf.lookups',
                "SPF uses {$lookups} DNS-lookup mechanisms, over the RFC 7208 limit of ".self::MAX_LOOKUPS.' (permerror).',
                ['record' => $record, 'lookups' => $lookups],
            );
        }

        if ($this->hasPassAll($record)) {
            $findings[] = Finding::warning(
                self::CATEGORY,
                'spf.all',
                'SPF ends in +all — every sender passes, defeating the record.',
                ['record' => $record],
            );
        }

        if ($findings === []) {
            $findings[] = Finding::info(
                self::CATEGORY,
                'spf.presence',
                "SPF is present and within the {$lookups}/".self::MAX_LOOKUPS.' lookup budget.',
                ['record' => $record, 'lookups' => $lookups],
            );
        }

        return $findings;
    }

    private function lookupCount(string $record): int
    {
        $count = 0;

        foreach ($this->terms($record) as $term) {
            $mechanism = strtolower(preg_replace('/^[+\-~?]/', '', $term) ?? $term);

            if (str_starts_with($mechanism, 'redirect=')) {
                $count++;

                continue;
            }

            $split = preg_split('/[:\/]/', $mechanism, 2);
            $name = strtolower(is_array($split) ? $split[0] : $mechanism);

            if (in_array($name, self::LOOKUP_MECHANISMS, true)) {
                $count++;
            }
        }

        return $count;
    }

    private function hasPassAll(string $record): bool
    {
        foreach ($this->terms($record) as $term) {
            // A bare `all` defaults to the `+` qualifier, so it is also pass-all.
            if ($term === 'all' || strcasecmp($term, '+all') === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * The whitespace-separated terms after the `v=spf1` version token.
     *
     * @return list<string>
     */
    private function terms(string $record): array
    {
        $parts = preg_split('/\s+/', trim($record)) ?: [];

        return array_values(array_filter(
            $parts,
            static fn (string $term): bool => $term !== '' && stripos($term, 'v=spf1') !== 0,
        ));
    }
}
