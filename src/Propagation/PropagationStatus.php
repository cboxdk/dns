<?php

declare(strict_types=1);

namespace Cbox\Dns\Propagation;

/**
 * The overall verdict of a propagation check, comparing the authoritative record
 * set against what the public recursive resolvers currently return.
 */
enum PropagationStatus: string
{
    /** Every public resolver agrees with the authoritative answer. */
    case Propagated = 'propagated';

    /** The authoritative answer is correct, but some recursives still serve a stale set. */
    case Pending = 'pending';

    /** The authoritative answer itself is missing or wrong — nothing can propagate yet. */
    case Misconfigured = 'misconfigured';
}
