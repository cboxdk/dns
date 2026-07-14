<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\Vectors;

it('exposes the RRSIG alongside the answer RRset', function (): void {
    $response = Vectors::dnskeyResponse();

    // records = only the queried DNSKEY type; answer = DNSKEYs + the RRSIG.
    expect($response->records)->toHaveCount(2)
        ->and($response->answer)->toHaveCount(3)
        ->and($response->answerOfType(RecordType::RRSIG))->toHaveCount(1)
        ->and($response->answerOfType(RecordType::DNSKEY))->toHaveCount(2);
});

it('captures the true owner name of each answer record', function (): void {
    foreach (Vectors::dnskeyResponse()->answer as $record) {
        expect($record->name)->toBe('cloudflare.com');
    }
});

it('parses the authority section (where NSEC/NSEC3 proofs live)', function (): void {
    $nsec = DenialFixtures::nsec('a.example.com', 'c.example.com', [RecordType::A, RecordType::NSEC, RecordType::RRSIG]);
    $rdata = (string) $nsec->raw;

    // Assemble a NODATA-style message: 1 question, 0 answers, 1 authority NSEC.
    $header = pack('n6', 0x1234, 0x8180, 1, 0, 1, 0);
    $question = WireName::encode('b.example.com', false).pack('n2', RecordType::A->code(), 1);
    $authorityRr = WireName::encode('a.example.com', false)
        .pack('n', RecordType::NSEC->code())
        .pack('n', 1)            // class IN
        .pack('N', 3600)         // TTL
        .pack('n', strlen($rdata))
        .$rdata;

    $message = $header.$question.$authorityRr;

    $response = (new Decoder)->decode($message, RecordType::A, 'b.example.com');

    expect($response->records)->toBeEmpty()
        ->and($response->authority)->toHaveCount(1)
        ->and($response->authorityOfType(RecordType::NSEC))->toHaveCount(1)
        ->and($response->authorityOfType(RecordType::NSEC)[0]->name)->toBe('a.example.com')
        ->and($response->authorityOfType(RecordType::NSEC)[0]->raw)->toBe($rdata);
});
