<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * A stored or received Domain Connect payload (provider settings, discovery
 * result) could not be read: a missing or wrongly typed field.
 */
class InvalidPayload extends DnsException
{
    public static function because(string $reason): self
    {
        return new self("Invalid Domain Connect payload: {$reason}.");
    }
}
