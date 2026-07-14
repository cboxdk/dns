<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Exceptions;

/**
 * An NSEC3 record demanded more hash iterations than the validator is willing to
 * compute (RFC 9276): a high iteration count is a CPU-amplification vector, so
 * the proof is refused before any hashing rather than paid for.
 */
class ExcessiveNsec3Iterations extends DnssecException
{
    public static function make(int $iterations, int $cap): self
    {
        return new self("NSEC3 iteration count {$iterations} exceeds the RFC 9276 cap of {$cap}.");
    }
}
