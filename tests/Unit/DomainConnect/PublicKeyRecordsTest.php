<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Exceptions\InvalidPayload;
use Cbox\Dns\DomainConnect\PublicKeyRecords;
use Cbox\Dns\DomainConnect\Signers\OpenSslRs256Signer;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

it('produces a signature the published key verifies', function (): void {
    $pem = PublicKeyRecords::toPem(PublicKeyRecords::for(DomainConnectFixture::file('test-public.pem')));
    $sig = base64_decode((new OpenSslRs256Signer(DomainConnectFixture::file('test-private.pem')))->sign('domain=example.net'));

    expect(openssl_verify('domain=example.net', $sig, $pem, OPENSSL_ALGO_SHA256))->toBe(1);
});

it('splits the key into p=n,a=RS256,d=chunk strings no longer than 255 bytes and rebuilds it from any order', function (): void {
    $publicPem = DomainConnectFixture::file('test-public.pem');
    $records = PublicKeyRecords::for($publicPem);

    expect($records)->toHaveCount(2)
        ->and($records[0])->toStartWith('p=1,a=RS256,d=')
        ->and($records[1])->toStartWith('p=2,a=RS256,d=')
        ->and(strlen($records[0]))->toBe(strlen('p=1,a=RS256,d=') + 200)
        ->and(max(array_map('strlen', $records)))->toBeLessThanOrEqual(255)
        ->and(PublicKeyRecords::toPem(array_reverse($records)))->toBe(PublicKeyRecords::toPem($records))
        ->and(PublicKeyRecords::toPem($records))->toBe($publicPem);
});

it('honours a smaller chunk size', function (): void {
    $records = PublicKeyRecords::for(DomainConnectFixture::file('test-public.pem'), 100);

    expect($records)->toHaveCount(4)
        ->and($records[3])->toStartWith('p=4,a=RS256,d=')
        ->and(PublicKeyRecords::toPem($records))->toBe(DomainConnectFixture::file('test-public.pem'));
});

it('refuses a chunk that would push a record past 255 bytes', function (): void {
    PublicKeyRecords::for(DomainConnectFixture::file('test-public.pem'), 236);
})->throws(InvalidPayload::class);

it('refuses anything but an RSA public key', function (string $fixture): void {
    PublicKeyRecords::for(DomainConnectFixture::file($fixture));
})->throws(InvalidPayload::class)->with([
    'the private key' => ['test-private.pem'],
    'an EC public key' => ['test-ec-public.pem'],
    'not a key' => ['README.md'],
]);

it('publishes a PKCS#1 RSA public key as its SPKI form', function (): void {
    $records = PublicKeyRecords::for(DomainConnectFixture::file('test-rsa-pkcs1-public.pem'));

    expect(PublicKeyRecords::toPem($records))->toBe(DomainConnectFixture::file('test-public.pem'));
});

it('ignores whitespace inside d=', function (): void {
    $records = PublicKeyRecords::for(DomainConnectFixture::file('test-public.pem'));
    $records[0] = substr($records[0], 0, 30).' '.substr($records[0], 30);

    expect(PublicKeyRecords::toPem($records))->toBe(DomainConnectFixture::file('test-public.pem'));
});

it('refuses a malformed record set', function (array $records): void {
    PublicKeyRecords::toPem($records);
})->throws(InvalidPayload::class)->with([
    'no p' => [['a=RS256,d=MIIB']],
    'no d' => [['p=1,a=RS256']],
    'not a record' => [['hello']],
    'p=0' => [['p=0,a=RS256,d=MIIB']],
    'duplicate p' => [['p=1,a=RS256,d=MIIB', 'p=1,a=RS256,d=AAAA']],
    'gap in p' => [['p=1,a=RS256,d=MIIB', 'p=3,a=RS256,d=AAAA']],
    'another algorithm' => [['p=1,a=ES256,d=MIIB']],
    'no records' => [[]],
]);
