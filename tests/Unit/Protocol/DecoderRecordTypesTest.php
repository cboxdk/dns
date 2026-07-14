<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\WireMessage;

it('decodes a TLSA record to its presentation form', function (): void {
    // usage=3, selector=1, matching=1, then 32 bytes of association data.
    $rdata = chr(3).chr(1).chr(1).str_repeat("\xAB", 32);
    $message = WireMessage::response(1, '_443._tcp.example.com', 52, [
        ['name' => '_443._tcp.example.com', 'type' => 52, 'rdata' => $rdata],
    ]);

    $record = (new Decoder)->decode($message, RecordType::TLSA, '_443._tcp.example.com')->records[0];

    expect($record->value)->toBe('3 1 1 '.str_repeat('ab', 32));
});

it('decodes an HTTPS (SVCB) record priority and target', function (): void {
    // priority=1, target "example.com", no params.
    $rdata = pack('n', 1).WireMessage::name('example.com');
    $message = WireMessage::response(1, 'example.com', 65, [
        ['name' => 'example.com', 'type' => 65, 'rdata' => $rdata],
    ]);

    $record = (new Decoder)->decode($message, RecordType::HTTPS, 'example.com')->records[0];

    expect($record->value)->toBe('1 example.com')
        ->and($record->priority)->toBe(1);
});

it('decodes a NAPTR record to its presentation form', function (): void {
    // order=100, preference=10, flags "S", service "SIP+D2U", empty regexp, replacement.
    $rdata = pack('n', 100).pack('n', 10)
        .chr(1).'S'
        .chr(7).'SIP+D2U'
        .chr(0)
        .WireMessage::name('_sip._udp.example.com');
    $message = WireMessage::response(1, 'example.com', 35, [
        ['name' => 'example.com', 'type' => 35, 'rdata' => $rdata],
    ]);

    $record = (new Decoder)->decode($message, RecordType::NAPTR, 'example.com')->records[0];

    expect($record->value)->toBe('100 10 "S" "SIP+D2U" "" _sip._udp.example.com')
        ->and($record->priority)->toBe(100);
});
