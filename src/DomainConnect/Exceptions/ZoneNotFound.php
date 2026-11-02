<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Exceptions;

use Cbox\Dns\Exceptions\DnsException;

/**
 * No zone apex could be found for a name: no SOA answered for it or any parent.
 */
class ZoneNotFound extends DnsException
{
    public static function for(string $name): self
    {
        return new self("No DNS zone found for [{$name}]: no SOA record answers for it or any parent.");
    }
}
