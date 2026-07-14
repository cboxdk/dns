<?php

declare(strict_types=1);

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\Address;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\Mx;
use Cbox\Dns\ValueObjects\Name;
use Cbox\Dns\ValueObjects\Txt;

it('exposes a typed object for an A record', function (): void {
    $data = (new DnsRecord(RecordType::A, 'example.com', '93.184.216.34'))->data();

    expect($data)->toBeInstanceOf(Address::class)
        ->and($data->ip)->toBe('93.184.216.34')
        ->and($data->ipv6)->toBeFalse()
        ->and($data->presentation())->toBe('93.184.216.34');
});

it('flags an AAAA record as IPv6', function (): void {
    expect((new DnsRecord(RecordType::AAAA, 'example.com', '2606:4700::1'))->data()->ipv6)->toBeTrue();
});

it('exposes a typed object for MX / CNAME / TXT', function (): void {
    $mx = (new DnsRecord(RecordType::MX, 'example.com', 'mail.example.com', priority: 10))->data();
    $cname = (new DnsRecord(RecordType::CNAME, 'www.example.com', 'example.com'))->data();
    $txt = (new DnsRecord(RecordType::TXT, 'example.com', 'v=spf1 -all'))->data();

    expect($mx)->toBeInstanceOf(Mx::class)
        ->and($mx->preference)->toBe(10)
        ->and($mx->exchange)->toBe('mail.example.com')
        ->and($cname)->toBeInstanceOf(Name::class)
        ->and($cname->name)->toBe('example.com')
        ->and($txt)->toBeInstanceOf(Txt::class)
        ->and($txt->text)->toBe('v=spf1 -all');
});

it('returns null for the DNSSEC types (handled by the Dnssec module)', function (RecordType $type): void {
    expect((new DnsRecord($type, 'example.com', base64_encode('x'), raw: 'x'))->data())->toBeNull();
})->with([
    RecordType::DS, RecordType::RRSIG, RecordType::DNSKEY, RecordType::NSEC, RecordType::NSEC3,
]);

it('yields a RecordData for every general-purpose type', function (RecordType $type, string $value, ?string $raw): void {
    expect((new DnsRecord($type, 'example.com', $value, priority: 10, raw: $raw))->data())
        ->toBeInstanceOf(RecordData::class);
})->with([
    'A' => [RecordType::A, '1.2.3.4', null],
    'AAAA' => [RecordType::AAAA, '::1', null],
    'CNAME' => [RecordType::CNAME, 'example.net', null],
    'NS' => [RecordType::NS, 'ns1.example.net', null],
    'PTR' => [RecordType::PTR, 'host.example.net', null],
    'TXT' => [RecordType::TXT, 'hello', null],
    'MX' => [RecordType::MX, 'mail.example.net', null],
    'SRV' => [RecordType::SRV, '5 5060 sip.example.net', null],
    'SOA' => [RecordType::SOA, 'ns hostmaster 1 2 3 4 5', null],
    'CAA' => [RecordType::CAA, '0 issue "letsencrypt.org"', null],
    'TLSA' => [RecordType::TLSA, '3 1 1  abcd', "\x03\x01\x01\xab\xcd"],
]);

it('returns the typed objects of a whole response, dropping DNSSEC records', function (): void {
    $response = new DnsResponse(RecordType::A, 'example.com', [
        new DnsRecord(RecordType::A, 'example.com', '1.1.1.1'),
        new DnsRecord(RecordType::A, 'example.com', '2.2.2.2'),
    ]);

    expect($response->data())->toHaveCount(2)
        ->and($response->data()[0])->toBeInstanceOf(Address::class);
});
