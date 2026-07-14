<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;

// A REAL response captured from 1.1.1.1 for `example.com TXT` — two TXT records
// (an SPF record and a verification-token-style string), a recursive (AA=0)
// answer with a compressed owner name (0xc00c pointer). Testing the decoder
// against genuine wire bytes, not a self-encoded fixture.
const EXAMPLE_COM_TXT = '123481800001000200000000076578616d706c6503636f6d00'
    .'00100001c00c001000010000012c000c0b763d73706631202d616c6c'
    .'c00c001000010000012c0021205f6b326e31793476773371746234736b6478396537647874393771726d6d7139';

it('decodes a real TXT response with two compressed records', function (): void {
    $message = hex2bin(EXAMPLE_COM_TXT);
    expect($message)->not->toBeFalse();

    $response = (new Decoder)->decode((string) $message, RecordType::TXT, 'example.com');

    expect($response->type)->toBe(RecordType::TXT)
        ->and($response->host)->toBe('example.com')
        ->and($response->authoritative)->toBeFalse()          // recursive answer, AA=0
        ->and($response->records)->toHaveCount(2)
        ->and($response->values())->toContain('v=spf1 -all')
        ->and($response->contains('_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9'))->toBeTrue();
});

it('reports a truncated message from the TC flag', function (): void {
    // Same header but with the TC bit (0x0200) set in the flags.
    $truncated = hex2bin('1234'.'8380'.'0001000000000000');
    expect(Decoder::isTruncated((string) $truncated))->toBeTrue();

    $clean = hex2bin(EXAMPLE_COM_TXT);
    expect(Decoder::isTruncated((string) $clean))->toBeFalse();
});

it('returns an empty response for NXDOMAIN without throwing', function (): void {
    // Header with RCODE=3 (NXDOMAIN), no answers.
    $nxdomain = hex2bin('1234'.'8183'.'0001000000000000'.'076578616d706c6503636f6d00'.'00100001');

    $response = (new Decoder)->decode((string) $nxdomain, RecordType::TXT, 'example.com');

    expect($response->isEmpty())->toBeTrue();
});
