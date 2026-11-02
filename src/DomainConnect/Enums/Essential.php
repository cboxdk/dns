<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Enums;

/**
 * Whether a record must always be in place (Always) or is only enforced
 * when the template is applied (OnApply), leaving the customer free to change it later.
 */
enum Essential: string
{
    case Always = 'Always';
    case OnApply = 'OnApply';
}
