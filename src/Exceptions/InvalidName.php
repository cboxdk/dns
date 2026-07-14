<?php

declare(strict_types=1);

namespace Cbox\Dns\Exceptions;

/**
 * A host name could not be encoded onto the wire — a label exceeds the 63-octet
 * limit (RFC 1035 §2.3.4), the whole name exceeds 255 octets, it carries an
 * illegal octet (e.g. an embedded NUL), or it is otherwise invalid.
 */
class InvalidName extends DnsException
{
    public static function make(string $host, string $reason = 'a label exceeds 63 octets'): self
    {
        return new self("Cannot encode DNS name [{$host}]: {$reason}.");
    }
}
