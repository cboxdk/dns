<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\WireMessage;
use Cbox\Dns\ValueObjects\Cert;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\Loc;
use Cbox\Dns\ValueObjects\Openpgpkey;
use Cbox\Dns\ValueObjects\Smimea;
use Cbox\Dns\ValueObjects\Sshfp;
use Cbox\Dns\ValueObjects\Uri;

function decodeOne(RecordType $type, string $rdata): DnsRecord
{
    return (new Decoder)->decode(
        WireMessage::response(1, 'example.com', $type->code(), [['name' => 'example.com', 'type' => $type->code(), 'rdata' => $rdata]]),
        $type,
        'example.com',
    )->records[0];
}

it('registers wire codes for all newly added types', function (): void {
    expect(RecordType::CERT->code())->toBe(37)
        ->and(RecordType::LOC->code())->toBe(29)
        ->and(RecordType::SSHFP->code())->toBe(44)
        ->and(RecordType::SMIMEA->code())->toBe(53)
        ->and(RecordType::OPENPGPKEY->code())->toBe(61)
        ->and(RecordType::URI->code())->toBe(256)
        ->and(RecordType::fromCode(256))->toBe(RecordType::URI);
});

it('decodes an SSHFP record', function (): void {
    $record = decodeOne(RecordType::SSHFP, chr(4).chr(2).str_repeat("\xAB", 32));
    $sshfp = $record->data();

    expect($sshfp)->toBeInstanceOf(Sshfp::class)
        ->and($sshfp->algorithm)->toBe(4)
        ->and($sshfp->fingerprintType)->toBe(2)
        ->and($sshfp->fingerprint)->toBe(str_repeat('ab', 32));
});

it('decodes an SMIMEA record like TLSA', function (): void {
    $smimea = decodeOne(RecordType::SMIMEA, chr(3).chr(0).chr(1).str_repeat("\xCD", 32))->data();

    expect($smimea)->toBeInstanceOf(Smimea::class)
        ->and($smimea->certificateUsage)->toBe(3)
        ->and($smimea->matchingType)->toBe(1);
});

it('decodes a URI record with priority, weight, and target', function (): void {
    $record = decodeOne(RecordType::URI, pack('n', 10).pack('n', 1).'https://example.com/');
    $uri = $record->data();

    expect($uri)->toBeInstanceOf(Uri::class)
        ->and($uri->priority)->toBe(10)
        ->and($uri->weight)->toBe(1)
        ->and($uri->target)->toBe('https://example.com/')
        ->and($record->value)->toBe('10 1 "https://example.com/"');
});

it('decodes a CERT record', function (): void {
    $cert = decodeOne(RecordType::CERT, pack('n', 1).pack('n', 12345).chr(8).'certbytes')->data();

    expect($cert)->toBeInstanceOf(Cert::class)
        ->and($cert->certificateType)->toBe(1)
        ->and($cert->keyTag)->toBe(12345)
        ->and($cert->algorithm)->toBe(8)
        ->and($cert->certificate)->toBe(base64_encode('certbytes'));
});

it('decodes an OPENPGPKEY record as base64', function (): void {
    $key = decodeOne(RecordType::OPENPGPKEY, 'rawkeybytes')->data();

    expect($key)->toBeInstanceOf(Openpgpkey::class)
        ->and($key->publicKey)->toBe(base64_encode('rawkeybytes'));
});

it('decodes a LOC record into degrees and metres', function (): void {
    // Build a LOC for ~52.0°N, 4.0°E, 10m altitude, 1m size/precision.
    $lat = 0x80000000 + (int) round(52.0 * 3_600_000);
    $lon = 0x80000000 + (int) round(4.0 * 3_600_000);
    $alt = 10_000_000 + 10 * 100; // 10 m above reference
    $sizeByte = 0x12;             // 1 * 10^2 cm = 1 m
    $rdata = chr(0).chr($sizeByte).chr($sizeByte).chr($sizeByte).pack('N', $lat).pack('N', $lon).pack('N', $alt);

    $loc = decodeOne(RecordType::LOC, $rdata)->data();

    expect($loc)->toBeInstanceOf(Loc::class)
        ->and(round($loc->latitude, 4))->toBe(52.0)
        ->and(round($loc->longitude, 4))->toBe(4.0)
        ->and(round($loc->altitude, 2))->toBe(10.0)
        ->and(round($loc->size, 2))->toBe(1.0)
        ->and($loc->presentation())->toContain('N')
        ->and($loc->presentation())->toContain('E');
});
