<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Enums;

/**
 * Which existing TXT records a template TXT record replaces when applied.
 */
enum TxtConflictMatchingMode: string
{
    case None = 'None';
    case All = 'All';
    case Prefix = 'Prefix';
}
