<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Ds;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use RuntimeException;

/**
 * Loaders for the captured, real cloudflare.com DNSSEC wire responses in
 * `tests/Fixtures`. These are genuine bytes from the network (algorithm 13,
 * ECDSA P-256/SHA-256; DS digest type 2, SHA-256), so verifying against them is
 * a real-vector proof, not a self-consistent mock.
 *
 * A validity instant is provided so tests pin the clock inside the captured
 * signatures' real inception/expiration window.
 */
final class Vectors
{
    // Inside the captured RRSIG(DNSKEY) window (inception 2026-07-09 .. 2026-09-08)
    // and the RRSIG(DS) window (2026-07-12 .. 2026-07-20).
    public const int WITHIN_VALIDITY = 1_784_000_000; // 2026-07-13T...

    public static function dnskeyResponse(): DnsResponse
    {
        return (new Decoder)->decode(self::load('cloudflare-dnskey.hex'), RecordType::DNSKEY, 'cloudflare.com');
    }

    public static function dsResponse(): DnsResponse
    {
        return (new Decoder)->decode(self::load('cloudflare-ds.hex'), RecordType::DS, 'cloudflare.com');
    }

    /**
     * The cloudflare.com KSK (key tag 2371) — the key the .com DS commits to and
     * the key that signs the DNSKEY RRset.
     */
    public static function ksk(): Dnskey
    {
        return self::keyWithTag(2371);
    }

    public static function zsk(): Dnskey
    {
        return self::keyWithTag(34505);
    }

    public static function dnskeyRrsig(): Rrsig
    {
        $records = self::dnskeyResponse()->answerOfType(RecordType::RRSIG);

        return Rrsig::fromRdata(self::raw($records[0]));
    }

    public static function ds(): Ds
    {
        return Ds::fromRdata(self::raw(self::dsResponse()->records[0]));
    }

    private static function keyWithTag(int $tag): Dnskey
    {
        foreach (self::dnskeyResponse()->records as $record) {
            $key = Dnskey::fromRdata(self::raw($record));

            if ($key->keyTag() === $tag) {
                return $key;
            }
        }

        throw new RuntimeException("no DNSKEY with tag {$tag}");
    }

    private static function raw(DnsRecord $record): string
    {
        if ($record->raw === null) {
            throw new RuntimeException('record has no raw RDATA');
        }

        return $record->raw;
    }

    private static function load(string $file): string
    {
        $hex = file_get_contents(__DIR__.'/../Fixtures/'.$file);

        if ($hex === false) {
            throw new RuntimeException("cannot read fixture {$file}");
        }

        $bytes = hex2bin(trim($hex));

        if ($bytes === false) {
            throw new RuntimeException("fixture {$file} is not valid hex");
        }

        return $bytes;
    }
}
