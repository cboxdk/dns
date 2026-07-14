<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics;

use Cbox\Dns\Diagnostics\Enums\Severity;

/**
 * The aggregated result of a diagnostic run: every {@see Finding} the checks
 * produced, plus the roll-ups a report or CLI needs — errors present, grouped by
 * severity, grouped by category, and a clean-bill `passed()` signal.
 */
readonly class Report
{
    /**
     * @param  list<Finding>  $findings
     */
    public function __construct(
        public array $findings,
    ) {}

    public function hasErrors(): bool
    {
        return $this->hasSeverity(Severity::Error);
    }

    /**
     * A clean bill of health: no errors AND no warnings (only info-level notes, or
     * nothing). Distinct from `! hasErrors()`, which still passes with warnings.
     */
    public function passed(): bool
    {
        return ! $this->hasErrors() && ! $this->hasSeverity(Severity::Warning);
    }

    /**
     * Findings grouped by severity value ("error" / "warning" / "info"). Only
     * severities that actually occurred appear as keys.
     *
     * @return array<string, list<Finding>>
     */
    public function bySeverity(): array
    {
        $grouped = [];

        foreach ($this->findings as $finding) {
            $grouped[$finding->severity->value][] = $finding;
        }

        return $grouped;
    }

    /**
     * Findings grouped by category ("Nameservers", "Email", …), in first-seen order.
     *
     * @return array<string, list<Finding>>
     */
    public function byCategory(): array
    {
        $grouped = [];

        foreach ($this->findings as $finding) {
            $grouped[$finding->category][] = $finding;
        }

        return $grouped;
    }

    private function hasSeverity(Severity $severity): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->severity === $severity) {
                return true;
            }
        }

        return false;
    }
}
