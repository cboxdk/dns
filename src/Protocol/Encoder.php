<?php

declare(strict_types=1);

namespace Cbox\Dns\Protocol;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\InvalidName;

/**
 * Builds a raw DNS query message (RFC 1035 §4.1). A single question, class IN.
 * `recursion` sets the RD bit — off when asking an authoritative server directly,
 * on when asking a recursive resolver. With `dnssec` set, an EDNS0 OPT RR with
 * the DO bit is appended (RFC 6891 / RFC 3225) so the server returns the DNSSEC
 * records (RRSIG/DNSKEY/DS/NSEC/NSEC3) needed for validation.
 */
class Encoder
{
    public function query(string $host, RecordType $type, bool $recursion = true, ?int $id = null, bool $dnssec = false): string
    {
        $id ??= random_int(0, 0xFFFF);
        $flags = $recursion ? 0x0100 : 0x0000; // RD bit
        $arcount = $dnssec ? 1 : 0;

        $header = pack('n6', $id, $flags, 1, 0, 0, $arcount);
        $question = $this->qname($host).pack('n2', $type->code(), 1); // QTYPE, QCLASS=IN

        return $header.$question.($dnssec ? $this->optRecord() : '');
    }

    /**
     * The EDNS0 OPT pseudo-record (RFC 6891 §6.1.2) that advertises a 4096-octet
     * UDP payload and sets the DO (DNSSEC OK) bit in the extended TTL. Root name,
     * TYPE 41 (OPT), CLASS = UDP payload size, TTL = extended-rcode(0) ‖ version(0)
     * ‖ flags(0x8000 = DO), RDLENGTH 0.
     */
    private function optRecord(): string
    {
        return "\x00"                    // root owner name
            .pack('n', 41)               // TYPE = OPT
            .pack('n', 4096)             // CLASS = requestor UDP payload size
            .pack('N', 0x00008000)       // TTL = DO bit set
            .pack('n', 0);               // RDLENGTH = 0
    }

    /**
     * Encode a domain name as length-prefixed labels terminated by the root.
     *
     * Rejects malformed names at the trust boundary rather than emitting a query
     * for the wrong name: an embedded NUL (or other illegal wire octet) is refused,
     * an empty interior label (`a..b`) — which would prematurely terminate the wire
     * name — is refused, and the total encoded length is capped at 255 octets
     * (RFC 1035 §2.3.4) as well as the 63-octet per-label limit.
     */
    public function qname(string $host): string
    {
        $host = trim($host, '.');
        $encoded = '';

        if ($host !== '') {
            foreach (explode('.', $host) as $label) {
                $length = strlen($label);

                if ($length === 0) {
                    throw InvalidName::make($host, 'the name has an empty label');
                }

                if ($length > 63) {
                    throw InvalidName::make($host, 'a label exceeds 63 octets');
                }

                if (str_contains($label, "\0")) {
                    throw InvalidName::make($host, 'a label contains an illegal NUL octet');
                }

                $encoded .= chr($length).$label;
            }
        }

        $encoded .= "\0"; // root label terminates the name

        if (strlen($encoded) > 255) {
            throw InvalidName::make($host, 'the encoded name exceeds 255 octets');
        }

        return $encoded;
    }
}
