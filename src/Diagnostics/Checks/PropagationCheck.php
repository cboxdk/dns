<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Propagation\PropagationChecker;
use Cbox\Dns\Propagation\PropagationStatus;
use Cbox\Dns\Propagation\ResolverResult;

/**
 * Wraps the {@see PropagationChecker} for the apex A record:
 * a fully `Propagated` set is Info; a `Pending` (some recursives still stale) or
 * `Misconfigured` (authoritative answer missing) result is a Warning. The reliable
 * signal here is the authoritative-vs-recursive diff, not geographic coverage.
 */
final class PropagationCheck implements Check
{
    private const string CATEGORY = 'Propagation';

    public function run(DiagnosticContext $ctx): array
    {
        $report = $ctx->propagation->check($ctx->domain, RecordType::A, $ctx->domain);

        $stale = array_map(
            static fn (ResolverResult $result): string => $result->nameserver,
            $report->stale(),
        );

        $context = [
            'status' => $report->status->value,
            'authoritative' => $report->authoritativeValues,
            'stale' => $stale,
        ];

        return [match ($report->status) {
            PropagationStatus::Propagated => Finding::info(
                self::CATEGORY,
                'propagation.apex-a',
                'The apex A record has propagated to every polled public resolver.',
                $context,
            ),
            PropagationStatus::Pending => Finding::warning(
                self::CATEGORY,
                'propagation.apex-a',
                'The apex A record has not yet propagated to every public resolver (in-flight TTL rollover).',
                $context,
            ),
            PropagationStatus::Misconfigured => Finding::warning(
                self::CATEGORY,
                'propagation.apex-a',
                'No authoritative apex A record to propagate — nothing to compare against.',
                $context,
            ),
        }];
    }
}
