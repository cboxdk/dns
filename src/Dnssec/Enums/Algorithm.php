<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Enums;

/**
 * The DNSSEC signing algorithms this validator recognises (IANA DNSSEC Algorithm
 * Numbers). Only algorithms listed here are ever accepted — {@see fromCode()}
 * returns null for anything else, and the verifier treats an unrecognised
 * algorithm as a validation FAILURE (deny-by-default, never a silent pass).
 *
 * Deliberately excluded (treated as unsupported → bogus): DSA (3/6), GOST
 * (12/23), Ed448 (16), and the "indirect"/reserved values. RSA/SHA-1 (5/7) are
 * kept only because they still appear in real chains; they are cryptographically
 * weak and callers should not depend on them.
 */
enum Algorithm: int
{
    case RSASHA1 = 5;
    case RSASHA1NSEC3SHA1 = 7;
    case RSASHA256 = 8;
    case RSASHA512 = 10;
    case ECDSAP256SHA256 = 13;
    case ECDSAP384SHA384 = 14;
    case ED25519 = 15;

    public static function fromCode(int $code): ?self
    {
        return self::tryFrom($code);
    }

    public function isRsa(): bool
    {
        return match ($this) {
            self::RSASHA1, self::RSASHA1NSEC3SHA1, self::RSASHA256, self::RSASHA512 => true,
            default => false,
        };
    }

    public function isEcdsa(): bool
    {
        return $this === self::ECDSAP256SHA256 || $this === self::ECDSAP384SHA384;
    }

    public function isEd25519(): bool
    {
        return $this === self::ED25519;
    }

    /**
     * The OpenSSL digest constant (`OPENSSL_ALGO_*`) used with `openssl_verify`
     * for the RSA and ECDSA families. Ed25519 hashes internally, so it has none.
     */
    public function opensslDigest(): ?int
    {
        return match ($this) {
            self::RSASHA1, self::RSASHA1NSEC3SHA1 => OPENSSL_ALGO_SHA1,
            self::RSASHA256, self::ECDSAP256SHA256 => OPENSSL_ALGO_SHA256,
            self::RSASHA512 => OPENSSL_ALGO_SHA512,
            self::ECDSAP384SHA384 => OPENSSL_ALGO_SHA384,
            self::ED25519 => null,
        };
    }

    /**
     * The fixed coordinate/component size for the ECDSA curves: 32 bytes for
     * P-256, 48 for P-384. Used to split the RRSIG's raw r‖s signature and to
     * validate the DNSKEY public-key length.
     */
    public function ecdsaComponentSize(): ?int
    {
        return match ($this) {
            self::ECDSAP256SHA256 => 32,
            self::ECDSAP384SHA384 => 48,
            default => null,
        };
    }
}
