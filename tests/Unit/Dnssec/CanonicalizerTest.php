<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\Canonicalizer;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DnsRecord;

function dummyRrsig(RecordType $type, string $signer = 'example.com'): Rrsig
{
    $prefix = pack('n', $type->code())
        .chr(13)                 // algorithm
        .chr(2)                  // labels
        .pack('N', 3600)         // original TTL
        .pack('N', 4_000_000_000)
        .pack('N', 1_700_000_000)
        .pack('n', 4242)
        .WireName::canonical($signer);

    return Rrsig::fromRdata($prefix."\x00");
}

it('sorts an RRset by canonical RDATA regardless of input order (RFC 4034 §6.3)', function (): void {
    $a1 = new DnsRecord(RecordType::A, 'example.com', '10.0.0.1', 3600, null, inet_pton('10.0.0.1'));
    $a2 = new DnsRecord(RecordType::A, 'example.com', '10.0.0.2', 3600, null, inet_pton('10.0.0.2'));

    $canon = new Canonicalizer;
    $rrsig = dummyRrsig(RecordType::A);

    $forward = $canon->signedData($rrsig, RecordType::A, [$a1, $a2]);
    $reverse = $canon->signedData($rrsig, RecordType::A, [$a2, $a1]);

    expect($forward)->toBe($reverse)
        ->and($forward)->toStartWith($rrsig->signedPrefix);
});

it('collapses duplicate RRs in the canonical RRset', function (): void {
    $a = new DnsRecord(RecordType::A, 'example.com', '10.0.0.1', 3600, null, inet_pton('10.0.0.1'));

    $canon = new Canonicalizer;
    $rrsig = dummyRrsig(RecordType::A);

    $single = $canon->signedData($rrsig, RecordType::A, [$a]);
    $duplicated = $canon->signedData($rrsig, RecordType::A, [$a, $a]);

    expect($single)->toBe($duplicated);
});

it('down-cases embedded names for name-bearing RDATA (MX)', function (): void {
    // 10 IN MX 10 MAIL.Example.COM.  vs the lowercase form.
    $upper = "\x00\x0a".WireName::encode('MAIL.Example.COM', false);
    $lower = "\x00\x0a".WireName::encode('mail.example.com', false);

    $recUpper = new DnsRecord(RecordType::MX, 'example.com', 'mail', 3600, 10, $upper);
    $recLower = new DnsRecord(RecordType::MX, 'example.com', 'mail', 3600, 10, $lower);

    $canon = new Canonicalizer;
    $rrsig = dummyRrsig(RecordType::MX);

    expect($canon->signedData($rrsig, RecordType::MX, [$recUpper]))
        ->toBe($canon->signedData($rrsig, RecordType::MX, [$recLower]));
});

it('down-cases the owner name and uses the RRSIG original TTL', function (): void {
    $recUpper = new DnsRecord(RecordType::A, 'EXAMPLE.com', '10.0.0.1', 60, null, inet_pton('10.0.0.1'));
    $recLower = new DnsRecord(RecordType::A, 'example.com', '10.0.0.1', 999, null, inet_pton('10.0.0.1'));

    $canon = new Canonicalizer;
    $rrsig = dummyRrsig(RecordType::A);

    // Owner case and the record's own TTL must not affect the canonical bytes.
    expect($canon->signedData($rrsig, RecordType::A, [$recUpper]))
        ->toBe($canon->signedData($rrsig, RecordType::A, [$recLower]));
});

it('reconstructs a wildcard owner name when the RRSIG label count is short', function (): void {
    // labels = 2 but owner has 3 labels → *.example.com
    $prefix = pack('n', RecordType::A->code())
        .chr(13).chr(2)          // algorithm, labels = 2
        .pack('N', 3600).pack('N', 4_000_000_000).pack('N', 1_700_000_000)
        .pack('n', 4242).WireName::canonical('example.com');
    $rrsig = Rrsig::fromRdata($prefix."\x00");

    $record = new DnsRecord(RecordType::A, 'host.example.com', '10.0.0.1', 3600, null, inet_pton('10.0.0.1'));

    $signed = (new Canonicalizer)->signedData($rrsig, RecordType::A, [$record]);

    // The canonical owner used is *.example.com, not host.example.com.
    expect($signed)->toContain(WireName::canonical('*.example.com'))
        ->and($signed)->not->toContain(WireName::canonical('host.example.com'));
});
