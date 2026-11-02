<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * A Domain Connect template could not be read: malformed JSON, a missing or
 * wrongly typed field, or an unknown record type.
 */
class InvalidTemplate extends DnsException
{
    public static function because(string $reason): self
    {
        return new self("Invalid Domain Connect template: {$reason}.");
    }
}
