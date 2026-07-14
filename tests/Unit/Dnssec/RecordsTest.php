<?php

declare(strict_types=1);

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;
use Cbox\Dns\Dnssec\Records\Dnskey;
use Cbox\Dns\Dnssec\Records\Nsec;
use Cbox\Dns\Dnssec\Records\Nsec3;
use Cbox\Dns\Dnssec\Records\Rrsig;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DenialFixtures;
use Cbox\Dns\Tests\Support\Vectors;

it('parses DNSKEY flags from the real vector', function (): void {
    $ksk = Vectors::ksk();
    $zsk = Vectors::zsk();

    expect($ksk->isSecureEntryPoint())->toBeTrue()
        ->and($ksk->isZoneKey())->toBeTrue()
        ->and($ksk->protocol)->toBe(3)
        ->and($ksk->algorithm)->toBe(13)
        ->and($zsk->isSecureEntryPoint())->toBeFalse()
        ->and($zsk->isZoneKey())->toBeTrue();
});

it('parses every RRSIG field from the real vector', function (): void {
    $rrsig = Vectors::dnskeyRrsig();

    expect($rrsig->typeCovered)->toBe(RecordType::DNSKEY->code())
        ->and($rrsig->algorithm)->toBe(13)
        ->and($rrsig->labels)->toBe(2)
        ->and($rrsig->originalTtl)->toBe(3600)
        ->and($rrsig->keyTag)->toBe(2371)
        ->and($rrsig->signerName)->toBe('cloudflare.com')
        ->and($rrsig->coversType(RecordType::DNSKEY))->toBeTrue()
        ->and(strlen($rrsig->signature))->toBe(64); // ECDSA P-256 r||s
});

it('parses an NSEC next-name and its type bitmap', function (): void {
    $record = DenialFixtures::nsec('a.example.com', 'c.example.com', [RecordType::A, RecordType::MX, RecordType::RRSIG]);
    $nsec = Nsec::fromRdata((string) $record->raw);

    expect($nsec->nextDomainName)->toBe('c.example.com')
        ->and($nsec->hasType(RecordType::A))->toBeTrue()
        ->and($nsec->hasType(RecordType::MX))->toBeTrue()
        ->and($nsec->hasType(RecordType::TXT))->toBeFalse();
});

it('parses NSEC3 fields including the Opt-Out flag', function (): void {
    $record = DenialFixtures::nsec3(
        str_repeat("\x11", 20),
        str_repeat("\x22", 20),
        12,
        "\xaa\xbb",
        [RecordType::A],
        'example.com',
        optOut: true,
    );
    $nsec3 = Nsec3::fromRdata((string) $record->raw);

    expect($nsec3->hashAlgorithm)->toBe(1)
        ->and($nsec3->iterations)->toBe(12)
        ->and($nsec3->salt)->toBe("\xaa\xbb")
        ->and($nsec3->nextHashedOwner)->toBe(str_repeat("\x22", 20))
        ->and($nsec3->isOptOut())->toBeTrue()
        ->and($nsec3->hasType(RecordType::A))->toBeTrue();
});

it('rejects malformed DNSSEC RDATA (deny-by-default parsing)', function (): void {
    expect(fn () => Dnskey::fromRdata("\x01\x02"))->toThrow(MalformedRdata::class)
        ->and(fn () => Rrsig::fromRdata("\x00\x00"))->toThrow(MalformedRdata::class);
});

it('rejects an RRSIG signer name that is compressed (pointer in signed RDATA)', function (): void {
    // 18-byte fixed header, then a 0xC0 compression pointer where the name starts.
    $rdata = str_repeat("\x00", 18)."\xc0\x0c".str_repeat("\x00", 32);

    expect(fn () => Rrsig::fromRdata($rdata))->toThrow(MalformedRdata::class);
});
