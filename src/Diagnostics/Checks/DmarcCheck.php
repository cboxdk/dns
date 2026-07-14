<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Checks;

use Cbox\Dns\Diagnostics\Contracts\Check;
use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\ValueObjects\DmarcPolicy;

/**
 * Checks the DMARC policy at `_dmarc.<domain>`: absent is a Warning (spoofed mail
 * cannot be reported or rejected); a malformed record or invalid `p=` policy is a
 * Warning; a valid but `p=none` policy is a Warning (monitor-only, no enforcement);
 * a valid `quarantine`/`reject` policy is Info.
 */
class DmarcCheck implements Check
{
    private const string CATEGORY = 'Email';

    private const array VALID_POLICIES = ['none', 'quarantine', 'reject'];

    public function run(DiagnosticContext $ctx): array
    {
        $host = '_dmarc.'.$ctx->domain;

        try {
            $records = $ctx->resolver->query($host, RecordType::TXT)->values();
        } catch (DnsException) {
            $records = [];
        }

        $dmarc = array_values(array_filter(
            $records,
            static fn (string $txt): bool => stripos(ltrim($txt), 'v=DMARC1') === 0,
        ));

        if ($dmarc === []) {
            return [Finding::warning(
                self::CATEGORY,
                'dmarc.presence',
                "No DMARC record at {$host} — receivers cannot report or act on spoofed mail.",
            )];
        }

        if (count($dmarc) > 1) {
            return [Finding::warning(
                self::CATEGORY,
                'dmarc.presence',
                'Multiple DMARC records published — receivers ignore DMARC entirely when more than one exists.',
                ['records' => $dmarc],
            )];
        }

        return [$this->evaluatePolicy($dmarc[0])];
    }

    private function evaluatePolicy(string $record): Finding
    {
        $dmarc = DmarcPolicy::parse($record);

        if ($dmarc === null || ! in_array($dmarc->policy, self::VALID_POLICIES, true)) {
            return Finding::warning(
                self::CATEGORY,
                'dmarc.policy',
                'DMARC record has no valid p= policy tag.',
                ['record' => $record, 'policy' => $dmarc?->policy],
            );
        }

        if ($dmarc->policy === 'none') {
            return Finding::warning(
                self::CATEGORY,
                'dmarc.policy',
                'DMARC policy is p=none — monitoring only, spoofed mail is not quarantined or rejected.',
                ['record' => $record, 'policy' => $dmarc->policy],
            );
        }

        return Finding::info(
            self::CATEGORY,
            'dmarc.policy',
            "DMARC is enforced with p={$dmarc->policy}.",
            ['record' => $record, 'policy' => $dmarc->policy, 'pct' => $dmarc->percentage],
        );
    }
}
