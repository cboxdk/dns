<?php

declare(strict_types=1);

namespace Cbox\Dns\Enums;

/**
 * The DNS response code (RFC 1035 §4.1.1, extended by later RFCs) — the 4-bit
 * RCODE field of a response header. It is the difference between "this name does
 * not exist" (NXDomain), "the name exists but has no record of this type" (a
 * NoError answer with an empty record set), and "the server broke" (ServFail) —
 * the core vocabulary a diagnostics or propagation tool must not collapse into a
 * single "empty" state.
 */
enum Rcode: int
{
    case NoError = 0;
    case FormErr = 1;
    case ServFail = 2;
    case NxDomain = 3;
    case NotImp = 4;
    case Refused = 5;
    case YxDomain = 6;
    case YxRrset = 7;
    case NxRrset = 8;
    case NotAuth = 9;
    case NotZone = 10;

    /**
     * Map a wire RCODE value to a case, falling back to {@see self::ServFail} for
     * any code this enum does not model — an unrecognised server error is treated
     * as a failure, never as success.
     */
    public static function fromCode(int $code): self
    {
        return self::tryFrom($code) ?? self::ServFail;
    }

    /**
     * A human-readable label for the code.
     */
    public function label(): string
    {
        return match ($this) {
            self::NoError => 'No error',
            self::FormErr => 'Format error',
            self::ServFail => 'Server failure',
            self::NxDomain => 'Non-existent domain',
            self::NotImp => 'Not implemented',
            self::Refused => 'Query refused',
            self::YxDomain => 'Name exists when it should not',
            self::YxRrset => 'RR set exists when it should not',
            self::NxRrset => 'RR set that should exist does not',
            self::NotAuth => 'Server not authoritative / not authorized',
            self::NotZone => 'Name not in zone',
        };
    }
}
