<?php

declare(strict_types=1);

use Cbox\Dns\Exceptions\MalformedMessage;
use Cbox\Dns\Protocol\Reader;
use Cbox\Dns\Tests\Support\WireMessage;

it('reads a compressed name that points backwards', function (): void {
    // "example.com" at offset 0 (13 bytes), then a pointer back to offset 0.
    $message = WireMessage::name('example.com').chr(0xC0).chr(0x00);
    $reader = new Reader($message);
    $reader->seek(13);

    expect($reader->name())->toBe('example.com');
});

it('rejects a forward compression pointer', function (): void {
    // A pointer at offset 0 pointing forward to offset 2.
    $message = chr(0xC0).chr(0x02).WireMessage::name('example.com');

    (new Reader($message))->name();
})->throws(MalformedMessage::class, 'point backwards');

it('rejects a self-referential compression pointer', function (): void {
    $message = chr(0xC0).chr(0x00);

    (new Reader($message))->name();
})->throws(MalformedMessage::class, 'point backwards');

it('throws rather than reading past the end of the message', function (): void {
    (new Reader("\x05abc"))->name();
})->throws(MalformedMessage::class, 'past end');
