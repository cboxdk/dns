<?php

declare(strict_types=1);

namespace Cbox\Dns\Protocol;

use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\MalformedMessage;
use Cbox\Dns\ValueObjects\Cdnskey;
use Cbox\Dns\ValueObjects\Cds;
use Cbox\Dns\ValueObjects\Cert;
use Cbox\Dns\ValueObjects\Csync;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\Eui;
use Cbox\Dns\ValueObjects\Hinfo;
use Cbox\Dns\ValueObjects\Kx;
use Cbox\Dns\ValueObjects\Loc;
use Cbox\Dns\ValueObjects\Naptr;
use Cbox\Dns\ValueObjects\Nsec3Param;
use Cbox\Dns\ValueObjects\Openpgpkey;
use Cbox\Dns\ValueObjects\Rp;
use Cbox\Dns\ValueObjects\Smimea;
use Cbox\Dns\ValueObjects\Sshfp;
use Cbox\Dns\ValueObjects\Svcb;
use Cbox\Dns\ValueObjects\Tlsa;
use Cbox\Dns\ValueObjects\Uri;
use Cbox\Dns\ValueObjects\Zonemd;

/**
 * Decodes a raw DNS response (RFC 1035 §4). Reads the header flags — the AA
 * (authoritative) bit matters for ownership verification — walks the answer
 * section, and parses the RDATA of the types we support. Every record is advanced
 * by its exact RDLENGTH, so an unknown or malformed RR can never desync the walk.
 */
class Decoder
{
    /**
     * Decode a response. When `$expectedId` is given (a live query, not a decode of
     * a captured message), the header ID and the echoed question are verified
     * against what was asked: a mismatched ID, question name, or question type is a
     * MALFORMED message, not a valid answer — this is the check that makes off-path
     * UDP spoofing hard. The name compare is case-insensitive by default (safe
     * against servers that normalise case); pass `$strictCase` to require an exact
     * case echo, which is what turns 0x20 mixed-case entropy into real extra bits.
     */
    public function decode(string $message, RecordType $expected, string $host, ?int $expectedId = null, bool $strictCase = false): DnsResponse
    {
        $reader = new Reader($message);

        $id = $reader->uint16();
        $flags = $reader->uint16();
        $qdcount = $reader->uint16();
        $ancount = $reader->uint16();
        $nscount = $reader->uint16();
        $arcount = $reader->uint16();

        $authoritative = ($flags & 0x0400) !== 0; // AA
        $authenticated = ($flags & 0x0020) !== 0; // AD (advisory — we validate ourselves)
        $rcode = Rcode::fromCode($flags & 0x000F);

        if ($expectedId !== null && $id !== $expectedId) {
            throw MalformedMessage::make('response transaction ID does not match the query');
        }

        // A validated response MUST echo the question — a zero-question reply cannot
        // be matched to the query and is refused rather than trusted.
        if ($expectedId !== null && $qdcount === 0) {
            throw MalformedMessage::make('response carried no question to match against the query');
        }

        for ($i = 0; $i < $qdcount; $i++) {
            $qname = $reader->name();
            $qtype = $reader->uint16();
            $reader->uint16();           // qclass

            // Verify the first question echoes what was asked (name + type). Case
            // is compared exactly only when 0x20 strict mode is on; otherwise a
            // case-insensitive compare keeps case-normalising servers working.
            if ($expectedId !== null && $i === 0) {
                $expectedName = rtrim($host, '.');
                $nameMatches = $strictCase
                    ? $qname === $expectedName
                    : strcasecmp($qname, $expectedName) === 0;

                if (! $nameMatches || $qtype !== $expected->code()) {
                    throw MalformedMessage::make('response question does not match the query');
                }
            }
        }

        // The answer and authority sections are both walked in full: DNSSEC needs
        // the RRSIGs that ride alongside the answer, and NSEC/NSEC3 denial proofs
        // live in the authority section (even on an NXDOMAIN, RCODE=3). Unknown
        // types are skipped by exact RDLENGTH so the walk can never desync.
        $answer = $this->section($reader, $message, $ancount);
        $authority = $this->section($reader, $message, $nscount);
        // The additional section carries glue (the A/AAAA of referral nameservers),
        // which a delegation trace needs to reach in-bailiwick child servers. It is
        // supplementary, so a malformed/count-inflated additional section is dropped
        // rather than sinking an otherwise-valid answer + authority.
        try {
            $additional = $this->section($reader, $message, $arcount);
        } catch (MalformedMessage) {
            $additional = [];
        }

        $records = array_values(array_filter(
            $answer,
            static fn (DnsRecord $r): bool => $r->type === $expected,
        ));

        return new DnsResponse(
            $expected,
            $host,
            $records,
            null,
            $authoritative,
            $authenticated,
            $answer,
            $authority,
            $rcode,
            $additional,
        );
    }

    /**
     * Read a whole RR section, returning every recognised record with its true
     * owner name. Unknown types advance by RDLENGTH and are dropped.
     *
     * @return list<DnsRecord>
     */
    private function section(Reader $reader, string $message, int $count): array
    {
        $records = [];

        for ($i = 0; $i < $count; $i++) {
            $owner = $reader->name();
            $type = $reader->uint16();
            $reader->uint16();           // class
            $ttl = $reader->uint32();
            $rdlength = $reader->uint16();
            $rdataStart = $reader->position();

            $recordType = RecordType::fromCode($type);

            if ($recordType !== null) {
                $raw = substr($message, $rdataStart, $rdlength);
                $records[] = $this->rdata($reader, $recordType, $owner, $ttl, $rdlength, $raw);
            }

            // Always resume exactly past this RR's RDATA — never trust our own
            // per-type parse to have consumed precisely RDLENGTH bytes.
            $reader->seek($rdataStart + $rdlength);
        }

        return $records;
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
            RecordType::CNAME, RecordType::NS, RecordType::PTR, RecordType::DNAME => $reader->name(),
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
            // The compound "exotic" types parse from their exact wire RDATA via the
            // dedicated value objects, so the decoder and a consumer's structured
            // access share one parser. A genuinely malformed RR degrades to the
            // RFC 3597 generic form rather than aborting the whole response.
            RecordType::NAPTR => (function () use ($raw, &$priority): string {
                $naptr = Naptr::fromRdata($raw);
                $priority = $naptr?->order;

                return $naptr?->presentation() ?? $this->generic($raw);
            })(),
            RecordType::TLSA => Tlsa::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::SMIMEA => Smimea::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::SSHFP => Sshfp::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::CERT => Cert::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::LOC => Loc::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::OPENPGPKEY => Openpgpkey::fromRdata($raw)->presentation(),
            RecordType::HINFO => Hinfo::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::RP => Rp::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::KX => (function () use ($raw, &$priority): string {
                $kx = Kx::fromRdata($raw);
                $priority = $kx?->preference;

                return $kx?->presentation() ?? $this->generic($raw);
            })(),
            RecordType::EUI48 => Eui::fromRdata($raw, 6)?->presentation() ?? $this->generic($raw),
            RecordType::EUI64 => Eui::fromRdata($raw, 8)?->presentation() ?? $this->generic($raw),
            RecordType::CDS => Cds::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::CDNSKEY => Cdnskey::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::NSEC3PARAM => Nsec3Param::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::CSYNC => Csync::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::ZONEMD => Zonemd::fromRdata($raw)?->presentation() ?? $this->generic($raw),
            RecordType::URI => (function () use ($raw, &$priority): string {
                $uri = Uri::fromRdata($raw);
                $priority = $uri?->priority;

                return $uri?->presentation() ?? $this->generic($raw);
            })(),
            RecordType::SVCB, RecordType::HTTPS => (function () use ($raw, &$priority): string {
                $svcb = Svcb::fromRdata($raw);
                $priority = $svcb?->priority;

                return $svcb?->presentation() ?? $this->generic($raw);
            })(),
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

    /**
     * The RFC 3597 §5 generic presentation of unknown/unparseable RDATA:
     * `\# <length> <hex>`. Used as a graceful fallback when a compound record's own
     * parser rejects the bytes, so one malformed RR never aborts the whole response.
     */
    private function generic(string $raw): string
    {
        return '\# '.strlen($raw).($raw === '' ? '' : ' '.bin2hex($raw));
    }
}
