<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\WireMessage;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\Naptr;
use Cbox\Dns\ValueObjects\Svcb;
use Cbox\Dns\ValueObjects\Tlsa;

it('parses a full HTTPS record — alpn, port, ipv4/ipv6 hints, ech, mandatory', function (): void {
    $params = ''
        .pack('n', 0).pack('n', 4).pack('n', 1).pack('n', 3)          // mandatory = alpn, port
        .pack('n', 1).pack('n', 6).chr(2).'h3'.chr(2).'h2'            // alpn = h3, h2
        .pack('n', 3).pack('n', 2).pack('n', 8443)                    // port = 8443
        .pack('n', 4).pack('n', 4).inet_pton('104.16.0.1')           // ipv4hint
        .pack('n', 5).pack('n', 3).'abc'                             // ech (opaque)
        .pack('n', 6).pack('n', 16).inet_pton('2606:4700::1');       // ipv6hint

    $rdata = pack('n', 1).WireMessage::name('example.com').$params;
    $record = (new Decoder)->decode(
        WireMessage::response(1, 'example.com', 65, [['name' => 'example.com', 'type' => 65, 'rdata' => $rdata]]),
        RecordType::HTTPS,
        'example.com',
    )->records[0];

    $svcb = Svcb::fromRecord($record);

    expect($svcb)->not->toBeNull()
        ->and($svcb->priority)->toBe(1)
        ->and($svcb->target)->toBe('example.com')
        ->and($svcb->alpn)->toBe(['h3', 'h2'])
        ->and($svcb->port)->toBe(8443)
        ->and($svcb->ipv4hint)->toBe(['104.16.0.1'])
        ->and($svcb->ipv6hint)->toBe(['2606:4700::1'])
        ->and($svcb->ech)->toBe(base64_encode('abc'))
        ->and($svcb->mandatory)->toBe([1, 3])
        ->and($record->value)->toBe('1 example.com mandatory=alpn,port alpn="h3,h2" port=8443 ipv4hint=104.16.0.1 ech='.base64_encode('abc').' ipv6hint=2606:4700::1');
});

it('treats HTTPS priority 0 as AliasMode', function (): void {
    $svcb = Svcb::fromRdata(pack('n', 0).WireMessage::name('svc.example.net'));

    expect($svcb?->isAlias())->toBeTrue()
        ->and($svcb?->target)->toBe('svc.example.net');
});

it('parses a TLSA record into typed DANE fields', function (): void {
    $record = new DnsRecord(RecordType::TLSA, '_443._tcp.example.com', '3 1 1 '.str_repeat('ab', 32), 300, raw: chr(3).chr(1).chr(1).str_repeat("\xAB", 32));
    $tlsa = Tlsa::fromRecord($record);

    expect($tlsa)->not->toBeNull()
        ->and($tlsa->certificateUsage)->toBe(3)
        ->and($tlsa->selector)->toBe(1)
        ->and($tlsa->matchingType)->toBe(1)
        ->and($tlsa->association)->toBe(str_repeat('ab', 32));
});

it('parses a NAPTR record into typed fields', function (): void {
    $raw = pack('n', 100).pack('n', 10).chr(1).'S'.chr(7).'SIP+D2U'.chr(0).WireMessage::name('_sip._udp.example.com');
    $naptr = Naptr::fromRdata($raw);

    expect($naptr)->not->toBeNull()
        ->and($naptr->order)->toBe(100)
        ->and($naptr->preference)->toBe(10)
        ->and($naptr->flags)->toBe('S')
        ->and($naptr->service)->toBe('SIP+D2U')
        ->and($naptr->regexp)->toBe('')
        ->and($naptr->replacement)->toBe('_sip._udp.example.com');
});

it('falls back to RFC 3597 generic form for a malformed exotic record', function (): void {
    // A truncated SVCB (priority only, no target/params) → generic \# form.
    $record = (new Decoder)->decode(
        WireMessage::response(1, 'example.com', 65, [['name' => 'example.com', 'type' => 65, 'rdata' => "\x00"]]),
        RecordType::HTTPS,
        'example.com',
    )->records[0];

    expect($record->value)->toStartWith('\# ');
});

it('returns null from fromRecord for a record without raw wire bytes (e.g. DoH)', function (): void {
    $record = new DnsRecord(RecordType::HTTPS, 'example.com', '1 .', 300);

    expect(Svcb::fromRecord($record))->toBeNull();
});
