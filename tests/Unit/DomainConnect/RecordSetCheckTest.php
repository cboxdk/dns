<?php

declare(strict_types=1);

use Cbox\Dns\Diagnostics\Diagnostics;
use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\ExpectedRecord;
use Cbox\Dns\DomainConnect\RecordSet;
use Cbox\Dns\DomainConnect\RecordSetCheck;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Tests\Support\DomainConnectFixture;
use Cbox\Dns\ValueObjects\DnsRecord;

it('reports every record present when the zone carries them, with a long TXT value', function (): void {
    $long = 'p=MIGf'.str_repeat('A', 240).'B'.str_repeat('C', 50);
    $set = RecordSet::fromTemplate(
        DomainConnectFixture::engageTemplate(),
        Zone::of('acme.example'),
        ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => substr($long, 2)],
    );
    $fake = DomainConnectFixture::liveZone()->stub('resend._domainkey.acme.example', RecordType::TXT, [$long], nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);

    expect($report->passed())->toBeTrue()
        ->and($report->findings)->toHaveCount(4)
        ->and($report->findings[0]->check)->toBe('domain-connect.present')
        ->and(array_map(fn ($f): string => $f->check, $report->findings))->each->toBe('domain-connect.present')
        ->and($report->findings[0]->category)->toBe('DomainConnect');
});

it('reports missing and mismatched records with the live values in context', function (): void {
    $fake = DomainConnectFixture::mxAt(DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP), 'other.example.', 10)
        ->stub('send.acme.example', RecordType::TXT, ['v=spf1 include:amazonses.com ~all'], nameserver: DomainConnectFixture::NS_IP)
        ->stub('resend._domainkey.acme.example', RecordType::TXT, ['p=OTHER'], nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck(DomainConnectFixture::engageSet())]);
    [$mx, $spf, $dkim, $dmarc] = $report->findings;

    expect($report->passed())->toBeFalse()
        ->and($mx->check)->toBe('domain-connect.mismatch')
        ->and($mx->context)->toBe(['name' => 'send.acme.example', 'type' => 'MX', 'expected' => '10 feedback-smtp.eu-west-1.amazonses.com', 'live' => ['10 other.example']])
        ->and($spf->check)->toBe('domain-connect.present')
        ->and($dkim->check)->toBe('domain-connect.mismatch')
        ->and($dkim->context['live'])->toBe(['p=OTHER'])
        ->and($dmarc->check)->toBe('domain-connect.missing')
        ->and($dmarc->context['live'])->toBe([]);
});

it('treats a wrong MX priority as a mismatch', function (): void {
    $fake = DomainConnectFixture::mxAt(DomainConnectFixture::liveZone(), 'feedback-smtp.eu-west-1.amazonses.com.', 20);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck(DomainConnectFixture::engageSet())]);

    expect($report->findings[0]->check)->toBe('domain-connect.mismatch')
        ->and($report->findings[0]->context['live'])->toBe(['20 feedback-smtp.eu-west-1.amazonses.com']);
});

it('accepts an SPF record that contains the rule among others', function (): void {
    $fake = DomainConnectFixture::liveZone(spf: ['v=spf1 a include:_spf.google.com include:amazonses.com ~all']);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck(DomainConnectFixture::engageSet())]);

    expect($report->findings[1]->check)->toBe('domain-connect.present');
});

it('flags an SPF record without the rule, or a rule that only matches as a substring', function (string $spf): void {
    $fake = DomainConnectFixture::liveZone(spf: ['some-other-txt', $spf]);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck(DomainConnectFixture::engageSet())]);

    expect($report->findings[1]->check)->toBe('domain-connect.mismatch')
        ->and($report->findings[1]->context['live'])->toBe(['some-other-txt', $spf]);
})->with([
    'rule absent' => 'v=spf1 include:_spf.google.com ~all',
    'substring only' => 'v=spf1 include:amazonses.com.evil.example ~all',
]);

it('reports SPFM missing when there is no TXT at the name at all', function (): void {
    $fake = DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck(DomainConnectFixture::engageSet())]);

    expect($report->findings[1]->check)->toBe('domain-connect.missing')
        ->and($report->findings[1]->context['live'])->toBe([]);
});

it('compares CNAME case-insensitively without the trailing dot, and A/AAAA exactly', function (): void {
    $template = DomainConnectFixture::templateWithRecords([
        ['type' => 'CNAME', 'host' => 'www', 'pointsTo' => 'Target.Example.'],
        ['type' => 'A', 'host' => 'app', 'pointsTo' => '203.0.113.5'],
        ['type' => 'AAAA', 'host' => 'app', 'pointsTo' => '2001:db8::5'],
        ['type' => 'APEXCNAME', 'host' => '@', 'pointsTo' => 'apex.example'],
    ]);
    $set = RecordSet::fromTemplate($template, Zone::of('acme.example'), []);
    $fake = DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP)
        ->stub('www.acme.example', RecordType::CNAME, ['TARGET.example'], nameserver: DomainConnectFixture::NS_IP)
        ->stub('app.acme.example', RecordType::A, ['203.0.113.5'], nameserver: DomainConnectFixture::NS_IP)
        ->stub('app.acme.example', RecordType::AAAA, ['2001:db8::6'], nameserver: DomainConnectFixture::NS_IP)
        ->stub('acme.example', RecordType::CNAME, ['apex.example.'], nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);

    expect(array_map(fn ($f): string => $f->check, $report->findings))->toBe([
        'domain-connect.present',
        'domain-connect.present',
        'domain-connect.mismatch',
        'domain-connect.present',
    ]);
});

it('reports SRV records as skipped and a failed query as missing', function (): void {
    $set = new RecordSet(Zone::of('acme.example'), [
        new ExpectedRecord(TemplateRecordType::SRV, '_sip._tcp.acme.example', 'sip.acme.example'),
        new ExpectedRecord(TemplateRecordType::TXT, 'x.acme.example', 'hello'),
    ]);
    $fake = DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP)
        ->stubFailure('x.acme.example', RecordType::TXT, nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);

    expect($report->findings[0]->check)->toBe('domain-connect.skipped')
        ->and($report->findings[0]->message)->toBe('SRV records are not checked.')
        ->and($report->findings[1]->check)->toBe('domain-connect.missing')
        ->and($report->findings[1]->context['live'])->toBe([]);
});

it('normalises an NS target', function (): void {
    $set = RecordSet::fromTemplate(DomainConnectFixture::templateWithRecords([
        ['type' => 'NS', 'host' => 'sub', 'pointsTo' => 'NS1.Other.Example.'],
    ]), Zone::of('acme.example'), []);
    $fake = DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP)
        ->stub('sub.acme.example', RecordType::NS, ['ns1.other.example'], nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);

    expect($report->findings[0]->check)->toBe('domain-connect.present');
});

it('reports a CNAME answer to an expected A as a mismatch with the target in live', function (): void {
    $set = RecordSet::fromTemplate(DomainConnectFixture::templateWithRecords([
        ['type' => 'A', 'host' => 'app', 'pointsTo' => '203.0.113.5'],
    ]), Zone::of('acme.example'), []);
    $fake = DomainConnectFixture::withAuthoritativeZone('acme.example', DomainConnectFixture::NS_IP)
        ->stubRecords('app.acme.example', RecordType::A, [
            new DnsRecord(RecordType::CNAME, 'app.acme.example', 'lb.other.example.'),
        ], nameserver: DomainConnectFixture::NS_IP);

    $report = (new Diagnostics($fake))->runWith('acme.example', [new RecordSetCheck($set)]);

    expect($report->findings[0]->check)->toBe('domain-connect.mismatch')
        ->and($report->findings[0]->context['live'])->toBe(['lb.other.example.']);
});
