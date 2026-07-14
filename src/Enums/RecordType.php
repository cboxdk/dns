<?php

declare(strict_types=1);

namespace Cbox\Dns\Enums;

/**
 * The DNS record types this package can look up. The string value is the
 * canonical mnemonic (as `dig` prints it); {@see code()} is the numeric TYPE
 * used on the wire (RFC 1035 and successors).
 */
enum RecordType: string
{
    case A = 'A';
    case AAAA = 'AAAA';
    case CNAME = 'CNAME';
    case MX = 'MX';
    case TXT = 'TXT';
    case NS = 'NS';
    case SOA = 'SOA';
    case PTR = 'PTR';
    case CAA = 'CAA';
    case SRV = 'SRV';

    /**
     * The on-the-wire numeric TYPE code.
     */
    public function code(): int
    {
        return match ($this) {
            self::A => 1,
            self::NS => 2,
            self::CNAME => 5,
            self::SOA => 6,
            self::PTR => 12,
            self::MX => 15,
            self::TXT => 16,
            self::AAAA => 28,
            self::SRV => 33,
            self::CAA => 257,
        };
    }

    public static function fromCode(int $code): ?self
    {
        foreach (self::cases() as $case) {
            if ($case->code() === $code) {
                return $case;
            }
        }

        return null;
    }
}
