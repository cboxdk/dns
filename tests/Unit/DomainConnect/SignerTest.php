<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Signers\OpenSslRs256Signer;
use Cbox\Dns\DomainConnect\Testing\FakeSigner;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

it('signs the spec example exactly as the openssl CLI does', function (): void {
    $signer = new OpenSslRs256Signer(DomainConnectFixture::file('test-private.pem'));

    expect($signer->sign('a=1&b=2&ip=10.10.10.10&domain=example.net'))
        ->toBe(trim(DomainConnectFixture::file('reference-signature.txt')));
});

it('returns standard base64 that the public key verifies', function (): void {
    $signature = (new OpenSslRs256Signer(DomainConnectFixture::file('test-private.pem')))->sign('domain=example.net');
    $raw = base64_decode($signature, true);

    expect($raw)->toBeString();

    expect($signature)->toMatch('#^[A-Za-z0-9+/]+={0,2}$#')
        ->and(strlen($raw))->toBe(256)
        ->and(openssl_verify('domain=example.net', $raw, DomainConnectFixture::file('test-public.pem'), OPENSSL_ALGO_SHA256))->toBe(1)
        ->and(openssl_verify('domain=example.org', $raw, DomainConnectFixture::file('test-public.pem'), OPENSSL_ALGO_SHA256))->toBe(0);
});

it('refuses a key it cannot read', function (): void {
    new OpenSslRs256Signer('not a key');
})->throws(RuntimeException::class, 'private key');

it('refuses a key that is not RSA', function (): void {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    expect($key)->not->toBeFalse();
    openssl_pkey_export($key, $pem);

    new OpenSslRs256Signer($pem);
})->throws(RuntimeException::class, 'RSA');

it('refuses an RSA key smaller than 2048 bits', function (): void {
    new OpenSslRs256Signer(DomainConnectFixture::file('test-rsa-1024.pem'));
})->throws(RuntimeException::class, 'at least 2048 bits');

it('keeps the private key out of stack traces', function (): void {
    $parameter = (new ReflectionMethod(OpenSslRs256Signer::class, '__construct'))->getParameters()[0];

    expect($parameter->getAttributes(SensitiveParameter::class))->toHaveCount(1);
});

it('fakes a fixed signature and records what it signed', function (): void {
    $signer = new FakeSigner;

    expect($signer->sign('a=1'))->toBe('ZmFrZS1zaWc=')
        ->and($signer->sign('b=2'))->toBe('ZmFrZS1zaWc=')
        ->and($signer->signed())->toBe(['a=1', 'b=2']);
});
