<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * An apply request does not fit its template: a variable is missing or
 * unknown, or a group id is not one the template defines.
 */
class InvalidApplyRequest extends DnsException
{
    public static function because(string $reason): self
    {
        return new self("Invalid Domain Connect apply request: {$reason}.");
    }
}
