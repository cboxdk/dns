<?php

declare(strict_types=1);

namespace Cbox\Dns\Exceptions;

/**
 * The bytes on the wire were not a well-formed DNS message (truncated, a name
 * pointer loop, an impossible length). Distinct from a query that simply found
 * no records.
 */
class MalformedMessage extends DnsException
{
    public static function make(string $reason): self
    {
        return new self("Malformed DNS message: {$reason}.");
    }
}
