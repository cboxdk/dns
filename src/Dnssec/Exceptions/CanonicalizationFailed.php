<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Exceptions;

/**
 * The canonical (RFC 4034 §6) form of an RRset could not be produced — most
 * often because a name-bearing RDATA field carried a compression pointer, which
 * a signed RR must never contain. Fail-closed: the verifier maps this to bogus
 * rather than guessing at the intended bytes.
 */
final class CanonicalizationFailed extends DnssecException
{
    public static function make(string $reason): self
    {
        return new self("DNSSEC canonicalization failed: {$reason}.");
    }
}
