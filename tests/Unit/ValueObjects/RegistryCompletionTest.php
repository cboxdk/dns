<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Tests\Support\WireMessage;
use Cbox\Dns\ValueObjects\Cds;
use Cbox\Dns\ValueObjects\Csync;
use Cbox\Dns\ValueObjects\Eui;
use Cbox\Dns\ValueObjects\Hinfo;
use Cbox\Dns\ValueObjects\Kx;
use Cbox\Dns\ValueObjects\Name;
use Cbox\Dns\ValueObjects\Nsec3Param;
use Cbox\Dns\ValueObjects\Rp;
use Cbox\Dns\ValueObjects\Zonemd;

function decodeType(RecordType $type, string $rdata): mixed
{
    return (new Decoder)->decode(
        WireMessage::response(1, 'example.com', $type->code(), [['name' => 'example.com', 'type' => $type->code(), 'rdata' => $rdata]]),
        $type,
        'example.com',
    )->records[0]->data();
}

it('assigns the correct IANA wire codes to the completion batch', function (): void {
    expect([
        RecordType::DNAME->code(), RecordType::HINFO->code(), RecordType::RP->code(),
        RecordType::KX->code(), RecordType::NSEC3PARAM->code(), RecordType::CDS->code(),
        RecordType::CDNSKEY->code(), RecordType::CSYNC->code(), RecordType::ZONEMD->code(),
        RecordType::EUI48->code(), RecordType::EUI64->code(),
    ])->toBe([39, 13, 17, 36, 51, 59, 60, 62, 63, 108, 109]);
});

it('decodes DNAME as a name', function (): void {
    expect(decodeType(RecordType::DNAME, WireMessage::name('target.example.net')))
        ->toBeInstanceOf(Name::class);
});

it('decodes HINFO into cpu and os', function (): void {
    $hinfo = decodeType(RecordType::HINFO, chr(4).'ARM6'.chr(5).'Linux');

    expect($hinfo)->toBeInstanceOf(Hinfo::class)
        ->and($hinfo->cpu)->toBe('ARM6')
        ->and($hinfo->os)->toBe('Linux');
});

it('decodes RP into mailbox and txt domain', function (): void {
    $rp = decodeType(RecordType::RP, WireMessage::name('admin.example.com').WireMessage::name('contact.example.com'));

    expect($rp)->toBeInstanceOf(Rp::class)
        ->and($rp->mailbox)->toBe('admin.example.com')
        ->and($rp->txtDomain)->toBe('contact.example.com');
});

it('decodes KX with a preference', function (): void {
    $kx = decodeType(RecordType::KX, pack('n', 5).WireMessage::name('kx.example.net'));

    expect($kx)->toBeInstanceOf(Kx::class)->and($kx->preference)->toBe(5);
});

it('decodes EUI48 and EUI64 as hyphenated hex', function (): void {
    expect(decodeType(RecordType::EUI48, hex2bin('00005e005301')))->toBeInstanceOf(Eui::class)
        ->and(decodeType(RecordType::EUI48, hex2bin('00005e005301'))->address)->toBe('00-00-5e-00-53-01')
        ->and(decodeType(RecordType::EUI64, hex2bin('00005e10000053f0'))->address)->toBe('00-00-5e-10-00-00-53-f0');
});

it('decodes CDS like DS', function (): void {
    $cds = decodeType(RecordType::CDS, pack('n', 12345).chr(13).chr(2).str_repeat("\xAB", 32));

    expect($cds)->toBeInstanceOf(Cds::class)
        ->and($cds->keyTag)->toBe(12345)
        ->and($cds->algorithm)->toBe(13)
        ->and($cds->digestType)->toBe(2);
});

it('decodes NSEC3PARAM with salt', function (): void {
    $param = decodeType(RecordType::NSEC3PARAM, chr(1).chr(0).pack('n', 10).chr(4).hex2bin('deadbeef'));

    expect($param)->toBeInstanceOf(Nsec3Param::class)
        ->and($param->iterations)->toBe(10)
        ->and($param->salt)->toBe('deadbeef');
});

it('decodes ZONEMD', function (): void {
    $zonemd = decodeType(RecordType::ZONEMD, pack('N', 2024010100).chr(1).chr(1).str_repeat("\xEE", 48));

    expect($zonemd)->toBeInstanceOf(Zonemd::class)
        ->and($zonemd->serial)->toBe(2024010100)
        ->and($zonemd->scheme)->toBe(1);
});

it('decodes CSYNC with a type bitmap into named types', function (): void {
    // window 0, length 4, bits for A (1), NS (2), AAAA (28).
    $bitmap = chr(0).chr(4).chr(0b01100000).chr(0).chr(0).chr(0b00001000);
    $csync = decodeType(RecordType::CSYNC, pack('N', 66).pack('n', 3).$bitmap);

    expect($csync)->toBeInstanceOf(Csync::class)
        ->and($csync->serial)->toBe(66)
        ->and($csync->typeNames())->toContain('A', 'NS', 'AAAA');
});
