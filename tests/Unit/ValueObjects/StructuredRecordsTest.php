<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\Caa;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\Soa;
use Cbox\Dns\ValueObjects\Srv;

it('parses an SOA presentation string into typed fields', function (): void {
    $soa = Soa::fromPresentation('ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600');

    expect($soa)->not->toBeNull()
        ->and($soa->mname)->toBe('ns1.example.com.')
        ->and($soa->serial)->toBe(2024010101)
        ->and($soa->refresh)->toBe(7200)
        ->and($soa->retry)->toBe(3600)
        ->and($soa->expire)->toBe(1209600)
        ->and($soa->minimum)->toBe(3600);
});

it('returns null for a malformed SOA string', function (): void {
    expect(Soa::fromPresentation('not enough fields'))->toBeNull();
});

it('builds an SRV value object from a record, folding in the priority', function (): void {
    $record = new DnsRecord(RecordType::SRV, '_sip._tcp.example.com', '20 5060 sipserver.example.com', 300, priority: 10);

    $srv = Srv::fromRecord($record);

    expect($srv)->not->toBeNull()
        ->and($srv->priority)->toBe(10)
        ->and($srv->weight)->toBe(20)
        ->and($srv->port)->toBe(5060)
        ->and($srv->target)->toBe('sipserver.example.com');
});

it('rejects a non-SRV record', function (): void {
    expect(Srv::fromRecord(new DnsRecord(RecordType::A, 'example.com', '1.2.3.4')))->toBeNull();
});

it('parses a CAA presentation string and reads the critical bit', function (): void {
    $caa = Caa::fromPresentation('128 issue "letsencrypt.org"');

    expect($caa)->not->toBeNull()
        ->and($caa->flags)->toBe(128)
        ->and($caa->tag)->toBe('issue')
        ->and($caa->value)->toBe('letsencrypt.org')
        ->and($caa->isCritical())->toBeTrue();

    expect(Caa::fromPresentation('0 issue "letsencrypt.org"')?->isCritical())->toBeFalse();
});
