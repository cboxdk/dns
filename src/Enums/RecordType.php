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
    case DNAME = 'DNAME';
    case MX = 'MX';
    case KX = 'KX';
    case TXT = 'TXT';
    case NS = 'NS';
    case SOA = 'SOA';
    case PTR = 'PTR';
    case HINFO = 'HINFO';
    case RP = 'RP';
    case CAA = 'CAA';
    case SRV = 'SRV';
    case NAPTR = 'NAPTR';
    case CERT = 'CERT';
    case LOC = 'LOC';
    case SSHFP = 'SSHFP';
    case SMIMEA = 'SMIMEA';
    case OPENPGPKEY = 'OPENPGPKEY';
    case EUI48 = 'EUI48';
    case EUI64 = 'EUI64';
    case URI = 'URI';
    case TLSA = 'TLSA';
    case SVCB = 'SVCB';
    case HTTPS = 'HTTPS';
    case DS = 'DS';
    case CDS = 'CDS';
    case RRSIG = 'RRSIG';
    case DNSKEY = 'DNSKEY';
    case CDNSKEY = 'CDNSKEY';
    case NSEC = 'NSEC';
    case NSEC3 = 'NSEC3';
    case NSEC3PARAM = 'NSEC3PARAM';
    case CSYNC = 'CSYNC';
    case ZONEMD = 'ZONEMD';

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
            self::HINFO => 13,
            self::MX => 15,
            self::TXT => 16,
            self::RP => 17,
            self::AAAA => 28,
            self::LOC => 29,
            self::SRV => 33,
            self::KX => 36,
            self::NAPTR => 35,
            self::CERT => 37,
            self::DNAME => 39,
            self::SSHFP => 44,
            self::TLSA => 52,
            self::SMIMEA => 53,
            self::OPENPGPKEY => 61,
            self::EUI48 => 108,
            self::EUI64 => 109,
            self::SVCB => 64,
            self::HTTPS => 65,
            self::URI => 256,
            self::DS => 43,
            self::CDS => 59,
            self::RRSIG => 46,
            self::NSEC => 47,
            self::DNSKEY => 48,
            self::CDNSKEY => 60,
            self::NSEC3 => 50,
            self::NSEC3PARAM => 51,
            self::CSYNC => 62,
            self::ZONEMD => 63,
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
