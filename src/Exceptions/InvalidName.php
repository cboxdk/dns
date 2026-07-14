<?php

declare(strict_types=1);

namespace Cbox\Dns\Exceptions;

/**
 * A host name could not be encoded onto the wire — a label exceeds the 63-octet
 * limit (RFC 1035 §2.3.4) or the name is otherwise invalid.
 */
final class InvalidName extends DnsException
{
    public static function make(string $host): self
    {
        return new self("Cannot encode DNS name [{$host}]: a label exceeds 63 octets.");
    }
}
