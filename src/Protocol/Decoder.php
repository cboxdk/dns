<?php

declare(strict_types=1);

namespace Cbox\Dns\Protocol;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\MalformedMessage;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * Decodes a raw DNS response (RFC 1035 §4). Reads the header flags — the AA
 * (authoritative) bit matters for ownership verification — walks the answer
 * section, and parses the RDATA of the types we support. Every record is advanced
 * by its exact RDLENGTH, so an unknown or malformed RR can never desync the walk.
 */
final class Decoder
{
    public function decode(string $message, RecordType $expected, string $host): DnsResponse
    {
        $reader = new Reader($message);

        $reader->uint16();               // id
        $flags = $reader->uint16();
        $qdcount = $reader->uint16();
        $ancount = $reader->uint16();
        $reader->uint16();               // nscount
        $reader->uint16();               // arcount

        $rcode = $flags & 0x0F;
        if ($rcode !== 0) {
            // NXDOMAIN (3) and friends simply mean "no such records" for our
            // purposes; return an empty, still-flagged response.
            return new DnsResponse($expected, $host, [], null, ($flags & 0x0400) !== 0);
        }

        for ($i = 0; $i < $qdcount; $i++) {
            $reader->name();
            $reader->uint16();           // qtype
            $reader->uint16();           // qclass
        }

        $records = [];

        for ($i = 0; $i < $ancount; $i++) {
            $reader->name();             // owner name
            $type = $reader->uint16();
            $reader->uint16();           // class
            $ttl = $reader->uint32();
            $rdlength = $reader->uint16();
            $rdataStart = $reader->position();

            $recordType = RecordType::fromCode($type);

            if ($recordType === $expected) {
                $raw = substr($message, $rdataStart, $rdlength);
                $records[] = $this->rdata($reader, $recordType, $host, $ttl, $rdlength, $raw);
            }

            // Always resume exactly past this RR's RDATA — never trust our own
            // per-type parse to have consumed precisely RDLENGTH bytes.
            $reader->seek($rdataStart + $rdlength);
        }

        return new DnsResponse($expected, $host, $records, null, ($flags & 0x0400) !== 0);
    }

    public static function isTruncated(string $message): bool
    {
        if (strlen($message) < 4) {
            return false;
        }

        $flags = (ord($message[2]) << 8) | ord($message[3]);

        return ($flags & 0x0200) !== 0; // TC bit
    }

    private function rdata(Reader $reader, RecordType $type, string $host, int $ttl, int $rdlength, string $raw): DnsRecord
    {
        $priority = null;

        $value = match ($type) {
            RecordType::A => $this->ip($reader->bytes(4)),
            RecordType::AAAA => $this->ip($reader->bytes(16)),
            RecordType::CNAME, RecordType::NS, RecordType::PTR => $reader->name(),
            RecordType::TXT => $this->txt($reader->bytes($rdlength)),
            RecordType::MX => (function () use ($reader, &$priority): string {
                $priority = $reader->uint16();

                return $reader->name();
            })(),
            RecordType::SRV => (function () use ($reader, &$priority): string {
                $priority = $reader->uint16();
                $weight = $reader->uint16();
                $port = $reader->uint16();

                return $weight.' '.$port.' '.$reader->name();
            })(),
            RecordType::SOA => $this->soa($reader),
            RecordType::CAA => $this->caa($reader, $rdlength),
            // DNSSEC records are surfaced as base64 of their raw RDATA; the Dnssec
            // module re-parses the structured fields from `raw` (kept verbatim so
            // canonical-form signature reconstruction stays byte-exact).
            RecordType::DS, RecordType::RRSIG, RecordType::DNSKEY,
            RecordType::NSEC, RecordType::NSEC3 => base64_encode($raw),
        };

        return new DnsRecord($type, $host, $value, $ttl, $priority, $raw);
    }

    private function ip(string $bytes): string
    {
        $ip = inet_ntop($bytes);

        if ($ip === false) {
            throw MalformedMessage::make('invalid address RDATA');
        }

        return $ip;
    }

    private function txt(string $rdata): string
    {
        $out = '';
        $offset = 0;
        $length = strlen($rdata);

        // A TXT RR is one or more <length-octet><string> character-strings.
        while ($offset < $length) {
            $chunk = ord($rdata[$offset]);
            $offset++;
            $out .= substr($rdata, $offset, $chunk);
            $offset += $chunk;
        }

        return $out;
    }

    private function soa(Reader $reader): string
    {
        $mname = $reader->name();
        $rname = $reader->name();
        $serial = $reader->uint32();
        $refresh = $reader->uint32();
        $retry = $reader->uint32();
        $expire = $reader->uint32();
        $minimum = $reader->uint32();

        return "{$mname} {$rname} {$serial} {$refresh} {$retry} {$expire} {$minimum}";
    }

    private function caa(Reader $reader, int $rdlength): string
    {
        $flags = $reader->uint8();
        $tagLength = $reader->uint8();
        $tag = $reader->bytes($tagLength);
        $value = $reader->bytes(max(0, $rdlength - 2 - $tagLength));

        return "{$flags} {$tag} \"{$value}\"";
    }
}
