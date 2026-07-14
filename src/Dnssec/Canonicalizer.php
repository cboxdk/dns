<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Exceptions\CanonicalizationFailed;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

/**
 * Reconstructs the exact byte string an RRSIG signs (RFC 4034 §6). That string is
 *
 *   RRSIG_RDATA(without the signature) ‖ SORTED( canonical RR ... )
 *
 * where each canonical RR is
 *
 *   owner(lowercased, uncompressed) ‖ TYPE ‖ CLASS ‖ original-TTL ‖ RDLEN ‖ RDATA
 *
 * with the original TTL taken from the RRSIG (not the RR's own TTL), and the
 * RRset sorted by canonical RDATA as a left-justified unsigned octet stream
 * (§6.3). Name-bearing RDATA is down-cased for the types RFC 4034 §6.2 (as
 * amended by RFC 6840 §5.1) requires; everything else is byte-verbatim.
 */
class Canonicalizer
{
    private const int CLASS_IN = 1;

    /**
     * @param  list<DnsRecord>  $records  the RRset covered by `$rrsig`
     */
    public function signedData(Rrsig $rrsig, RecordType $type, array $records): string
    {
        if ($records === []) {
            throw CanonicalizationFailed::make('empty RRset cannot be canonicalized');
        }

        $owner = $this->ownerWire($rrsig, $records[0]->name);

        $encoded = [];

        foreach ($records as $record) {
            if ($record->raw === null) {
                throw CanonicalizationFailed::make('record is missing verbatim RDATA');
            }

            $rdata = $this->canonicalRdata($type, $record->raw);

            $encoded[] = $owner
                .pack('n', $type->code())
                .pack('n', self::CLASS_IN)
                .pack('N', $rrsig->originalTtl)
                .pack('n', strlen($rdata))
                .$rdata;
        }

        // §6.3: sort by the full canonical RR octet stream; duplicates collapse.
        // Since owner/type/class/ttl/rdlen are identical across the set, this is
        // equivalent to sorting by canonical RDATA. `sort` with SORT_STRING is a
        // bytewise (unsigned-octet) comparison.
        $encoded = array_values(array_unique($encoded));
        sort($encoded, SORT_STRING);

        return $rrsig->signedPrefix.implode('', $encoded);
    }

    /**
     * The canonical owner name in wire form. For a wildcard-synthesized RRset —
     * where the RRSIG's label count is fewer than the owner's labels — the name
     * is reconstructed as `*.<closest-encloser>` (RFC 4035 §5.3.2).
     */
    private function ownerWire(Rrsig $rrsig, string $name): string
    {
        $name = rtrim($name, '.');
        $labels = $name === '' ? [] : explode('.', $name);

        if ($rrsig->labels < count($labels)) {
            $suffix = array_slice($labels, count($labels) - $rrsig->labels);
            $name = '*'.($suffix === [] ? '' : '.'.implode('.', $suffix));
        }

        return WireName::canonical($name);
    }

    /**
     * Canonical RDATA for one RR. Down-cases embedded names for the RFC 4034 §6.2
     * name-bearing types; all other types (including DNSKEY, DS, NSEC — whose next
     * name is NOT down-cased per RFC 6840 §5.1 — and NSEC3) are byte-verbatim.
     */
    private function canonicalRdata(RecordType $type, string $raw): string
    {
        return match ($type) {
            RecordType::NS, RecordType::CNAME, RecordType::PTR => $this->singleName($raw),
            RecordType::SOA => $this->soa($raw),
            RecordType::MX => $this->mx($raw),
            RecordType::SRV => $this->srv($raw),
            default => $raw,
        };
    }

    private function singleName(string $raw): string
    {
        [$name, $offset] = WireName::read($raw, 0);

        $this->assertConsumed($offset, $raw);

        return WireName::canonical($name);
    }

    private function soa(string $raw): string
    {
        [$mname, $offset] = WireName::read($raw, 0);
        [$rname, $offset] = WireName::read($raw, $offset);

        // The five 32-bit fields (serial, refresh, retry, expire, minimum).
        if (strlen($raw) - $offset !== 20) {
            throw CanonicalizationFailed::make('SOA RDATA has an unexpected trailing length');
        }

        return WireName::canonical($mname).WireName::canonical($rname).substr($raw, $offset);
    }

    private function mx(string $raw): string
    {
        if (strlen($raw) < 3) {
            throw CanonicalizationFailed::make('MX RDATA shorter than 3 octets');
        }

        [$exchange, $offset] = WireName::read($raw, 2);

        $this->assertConsumed($offset, $raw);

        return substr($raw, 0, 2).WireName::canonical($exchange);
    }

    private function srv(string $raw): string
    {
        if (strlen($raw) < 7) {
            throw CanonicalizationFailed::make('SRV RDATA shorter than 7 octets');
        }

        [$target, $offset] = WireName::read($raw, 6);

        $this->assertConsumed($offset, $raw);

        return substr($raw, 0, 6).WireName::canonical($target);
    }

    private function assertConsumed(int $offset, string $raw): void
    {
        if ($offset !== strlen($raw)) {
            throw CanonicalizationFailed::make('trailing octets after RDATA name');
        }
    }
}
