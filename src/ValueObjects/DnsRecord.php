<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Dnssec;
use Cbox\Dns\Enums\RecordType;

/**
 * A single resolved DNS record. `value` is the record's presentation form as a
 * string (an IP for A/AAAA, the exchange host for MX, the joined text for TXT, …),
 * kept for display, comparison, and {@see DnsResponse::values()}.
 *
 * For typed access, call {@see self::data()} — it returns a {@see RecordData} value
 * object (`Address`, `Mx`, `Srv`, `Soa`, `Caa`, `Naptr`, `Tlsa`, `Svcb`, …) so a
 * consumer reads `->port` / `->exchange` / `->alpn` instead of parsing strings.
 *
 * `raw` holds the exact on-the-wire RDATA bytes. It is an internal detail — needed
 * for DNSSEC canonical-form signature reconstruction (where a normalized value
 * would lose byte fidelity) and as the parse source for the compound value objects
 * — not something a consumer should read directly.
 */
readonly class DnsRecord
{
    public function __construct(
        public RecordType $type,
        public string $name,
        public string $value,
        public int $ttl = 0,
        public ?int $priority = null,
        public ?string $raw = null,
    ) {}

    /**
     * The typed value object for this record, or null when the type has no
     * general-purpose object here. The DNSSEC types (DNSKEY/DS/RRSIG/NSEC/NSEC3)
     * return null: they are parsed and validated by the {@see Dnssec}
     * module, reached via `$dns->dnssec()`, not through this accessor. A compound
     * type read over DoH (which carries no raw RDATA) may also return null.
     */
    public function data(): ?RecordData
    {
        return match ($this->type) {
            RecordType::A => new Address($this->value, false),
            RecordType::AAAA => new Address($this->value, true),
            RecordType::CNAME, RecordType::NS, RecordType::PTR, RecordType::DNAME => new Name($this->value),
            RecordType::TXT => new Txt($this->value),
            RecordType::MX => Mx::fromRecord($this),
            RecordType::KX => Kx::fromRecord($this),
            RecordType::SRV => Srv::fromRecord($this),
            RecordType::SOA => Soa::fromPresentation($this->value),
            RecordType::CAA => Caa::fromPresentation($this->value),
            RecordType::NAPTR => Naptr::fromRecord($this),
            RecordType::HINFO => Hinfo::fromRecord($this),
            RecordType::RP => Rp::fromRecord($this),
            RecordType::TLSA => Tlsa::fromRecord($this),
            RecordType::SMIMEA => Smimea::fromRecord($this),
            RecordType::SSHFP => Sshfp::fromRecord($this),
            RecordType::CERT => Cert::fromRecord($this),
            RecordType::LOC => Loc::fromRecord($this),
            RecordType::OPENPGPKEY => Openpgpkey::fromRecord($this),
            RecordType::EUI48, RecordType::EUI64 => Eui::fromRecord($this),
            RecordType::URI => Uri::fromRecord($this),
            RecordType::CDS => Cds::fromRecord($this),
            RecordType::CDNSKEY => Cdnskey::fromRecord($this),
            RecordType::NSEC3PARAM => Nsec3Param::fromRecord($this),
            RecordType::CSYNC => Csync::fromRecord($this),
            RecordType::ZONEMD => Zonemd::fromRecord($this),
            RecordType::SVCB, RecordType::HTTPS => Svcb::fromRecord($this),
            RecordType::DS, RecordType::RRSIG, RecordType::DNSKEY,
            RecordType::NSEC, RecordType::NSEC3 => null,
        };
    }
}
