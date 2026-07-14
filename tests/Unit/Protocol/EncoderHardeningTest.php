<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\InvalidName;
use Cbox\Dns\Protocol\Encoder;

it('rejects a label longer than 63 octets', function (): void {
    (new Encoder)->qname(str_repeat('a', 64).'.example.com');
})->throws(InvalidName::class, 'exceeds 63 octets');

it('rejects an embedded NUL octet in a label', function (): void {
    (new Encoder)->qname("ex\0ample.com");
})->throws(InvalidName::class, 'NUL');

it('rejects an empty interior label that would truncate the wire name', function (): void {
    (new Encoder)->qname('a..b.example.com');
})->throws(InvalidName::class, 'empty label');

it('rejects a name whose encoded length exceeds 255 octets', function (): void {
    $label = str_repeat('a', 63);
    (new Encoder)->qname("{$label}.{$label}.{$label}.{$label}.example.com");
})->throws(InvalidName::class, 'exceeds 255 octets');

it('still encodes a normal name and the root', function (): void {
    $encoder = new Encoder;

    expect($encoder->query('example.com', RecordType::A))->toBeString()
        ->and($encoder->qname(''))->toBe("\0");
});
