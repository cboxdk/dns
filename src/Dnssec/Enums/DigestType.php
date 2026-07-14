<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Enums;

/**
 * The DS digest algorithms this validator accepts (IANA DS RR Type Digest
 * Algorithms). SHA-256 (2) and SHA-384 (4) only — SHA-1 (1) is deprecated and
 * GOST (3) is unsupported, so both resolve to null here and a DS using them is
 * rejected (deny-by-default: an unmatched digest link is never trusted).
 */
enum DigestType: int
{
    case SHA256 = 2;
    case SHA384 = 4;

    public static function fromCode(int $code): ?self
    {
        return self::tryFrom($code);
    }

    /**
     * The PHP `hash()` algorithm name for this digest.
     */
    public function hashAlgo(): string
    {
        return match ($this) {
            self::SHA256 => 'sha256',
            self::SHA384 => 'sha384',
        };
    }
}
