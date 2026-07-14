<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Exceptions;

/**
 * A DNSSEC RR's RDATA could not be parsed into its structured fields — too short,
 * an impossible length, or a field that runs past the end of the record.
 */
final class MalformedRdata extends DnssecException
{
    public static function make(string $reason): self
    {
        return new self("Malformed DNSSEC RDATA: {$reason}.");
    }
}
