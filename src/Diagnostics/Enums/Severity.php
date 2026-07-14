<?php

declare(strict_types=1);

namespace Cbox\Dns\Diagnostics\Enums;

use Cbox\Dns\Diagnostics\Finding;

/**
 * How serious a diagnostic {@see Finding} is.
 *
 * - `Error`   — a misconfiguration that breaks resolution, mail, or trust.
 * - `Warning` — works today, but fragile, non-redundant, or below best practice.
 * - `Info`    — an observation or a healthy result worth surfacing.
 */
enum Severity: string
{
    case Error = 'error';
    case Warning = 'warning';
    case Info = 'info';
}
