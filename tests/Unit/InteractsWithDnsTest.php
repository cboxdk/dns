<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Testing\InteractsWithDns;

uses(InteractsWithDns::class);

it('drives domain verification offline through the trait', function (): void {
    $this->stubZone('example.com', ['ns1.example.com' => '10.0.0.53'])
        ->stub('_myapp.example.com', RecordType::TXT, ['tok-123'], nameserver: '10.0.0.53');

    $dns = $this->fakeDnsFacade(challengePrefix: '_myapp');

    expect($dns->challengeHost('example.com'))->toBe('_myapp.example.com')
        ->and($dns->verifyDomain('example.com', 'tok-123'))->toBeTrue()
        ->and($dns->verifyDomain('example.com', 'wrong'))->toBeFalse();
});

it('records the authoritative query the verification made', function (): void {
    $this->stubZone('example.com', ['ns1.example.com' => '10.0.0.53'])
        ->stub('_cbox-challenge.example.com', RecordType::TXT, ['tok'], nameserver: '10.0.0.53');

    $this->fakeDnsFacade()->verifyDomain('example.com', 'tok');

    expect(fn () => $this->fakeDns()->assertQueried('_cbox-challenge.example.com', RecordType::TXT, '10.0.0.53'))
        ->not->toThrow(RuntimeException::class);
});
