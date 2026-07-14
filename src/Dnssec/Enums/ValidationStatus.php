<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Enums;

/**
 * The three RFC 4033 §5 security states a validation can resolve to.
 *
 * - `Secure`   — a complete authentication chain from a trust anchor was proven.
 * - `Insecure` — an authenticated proof exists that the zone is NOT signed
 *                (a delegation with no DS, proven via NSEC/NSEC3). Absence of
 *                DNSSEC, provably and legitimately.
 * - `Bogus`    — validation was expected to succeed but failed: a missing key,
 *                a broken DS link, a bad or expired signature, or an unknown
 *                algorithm. This is the deny-by-default outcome — anything that
 *                is not provably Secure or provably Insecure is Bogus.
 */
enum ValidationStatus: string
{
    case Secure = 'secure';
    case Insecure = 'insecure';
    case Bogus = 'bogus';
}
