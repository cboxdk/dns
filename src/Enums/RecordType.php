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
    case DS = 'DS';
    case RRSIG = 'RRSIG';
    case DNSKEY = 'DNSKEY';
    case NSEC = 'NSEC';
    case NSEC3 = 'NSEC3';

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
            self::DS => 43,
            self::RRSIG => 46,
            self::NSEC => 47,
            self::DNSKEY => 48,
            self::NSEC3 => 50,
            self::CAA => 257,
        };
    }

    /**
     * The DNSSEC record types — carried as raw RDATA (structured parsing lives in
     * the Dnssec module), so the decoder never has to understand their internals.
     */
    public function isDnssec(): bool
    {
        return in_array($this, [self::DS, self::RRSIG, self::DNSKEY, self::NSEC, self::NSEC3], true);
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
