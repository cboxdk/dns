<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Contracts;

use Cbox\Dns\Diagnostics\DiagnosticContext;
use Cbox\Dns\Diagnostics\Finding;

/**
 * One diagnostic check. Given the {@see DiagnosticContext} (the target domain plus
 * the injected resolvers), it returns every {@see Finding} it produced — errors,
 * warnings, and the healthy-case info notes. A check never throws for a DNS-level
 * failure; it turns that failure into a Finding, so the orchestrator always gets a
 * complete report.
 */
interface Check
{
    /**
     * @return list<Finding>
     */
    public function run(DiagnosticContext $ctx): array;
}
