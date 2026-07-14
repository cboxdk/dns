<?php

declare(strict_types=1);

use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\MalformedMessage;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\WireMessage;

it('decodes the RCODE so NXDOMAIN, SERVFAIL, and NODATA are distinguishable', function (): void {
    $decoder = new Decoder;

    $nxdomain = $decoder->decode(WireMessage::response(1, 'nope.example.com', 1, rcode: 3), RecordType::A, 'nope.example.com');
    $servfail = $decoder->decode(WireMessage::response(2, 'broken.example.com', 1, rcode: 2), RecordType::A, 'broken.example.com');
    $nodata = $decoder->decode(WireMessage::response(3, 'example.com', 1, rcode: 0), RecordType::A, 'example.com');

    expect($nxdomain->rcode)->toBe(Rcode::NxDomain)
        ->and($nxdomain->isNxDomain())->toBeTrue()
        ->and($servfail->isServFail())->toBeTrue()
        ->and($nodata->succeeded())->toBeTrue()
        ->and($nodata->records)->toBe([]);
});

it('rejects a response whose transaction ID does not match the query', function (): void {
    $message = WireMessage::response(0x1234, 'example.com', 1, [
        ['name' => 'example.com', 'type' => 1, 'rdata' => WireMessage::a('93.184.216.34')],
    ]);

    (new Decoder)->decode($message, RecordType::A, 'example.com', expectedId: 0x9999);
})->throws(MalformedMessage::class, 'transaction ID');

it('rejects a response whose question does not echo the queried name', function (): void {
    $message = WireMessage::response(0x1234, 'attacker.example.com', 1);

    (new Decoder)->decode($message, RecordType::A, 'example.com', expectedId: 0x1234);
})->throws(MalformedMessage::class, 'question does not match');

it('rejects a response whose question type does not match', function (): void {
    $message = WireMessage::response(0x1234, 'example.com', 28 /* AAAA */);

    (new Decoder)->decode($message, RecordType::A, 'example.com', expectedId: 0x1234);
})->throws(MalformedMessage::class, 'question does not match');

it('rejects a validated response that echoes no question at all', function (): void {
    // Header claims qdcount=0; the ID matches but there is nothing to match against.
    $message = pack('n6', 0x1234, 0x8000, 0, 0, 0, 0);

    (new Decoder)->decode($message, RecordType::A, 'example.com', expectedId: 0x1234);
})->throws(MalformedMessage::class, 'no question');

it('accepts a matching ID and question and returns the record', function (): void {
    $message = WireMessage::response(0x1234, 'example.com', 1, [
        ['name' => 'example.com', 'type' => 1, 'rdata' => WireMessage::a('93.184.216.34')],
    ]);

    $response = (new Decoder)->decode($message, RecordType::A, 'example.com', expectedId: 0x1234);

    expect($response->values())->toBe(['93.184.216.34']);
});

it('accepts a case-differing question echo by default but rejects it in strict 0x20 mode', function (): void {
    $message = WireMessage::response(0x1234, 'EXAMPLE.com', 1);
    $decoder = new Decoder;

    expect($decoder->decode($message, RecordType::A, 'example.com', expectedId: 0x1234)->succeeded())->toBeTrue();

    $decoder->decode($message, RecordType::A, 'example.com', expectedId: 0x1234, strictCase: true);
})->throws(MalformedMessage::class);
