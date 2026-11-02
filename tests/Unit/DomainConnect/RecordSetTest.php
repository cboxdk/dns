<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\Exceptions\InvalidApplyRequest;
use Cbox\Dns\DomainConnect\ExpectedRecord;
use Cbox\Dns\DomainConnect\RecordSet;
use Cbox\Dns\DomainConnect\Zone;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

const ENGAGE_VARS = ['mx' => 'feedback-smtp.eu-west-1.amazonses.com', 'dkim' => 'MIGf'];

it('expands the engage template for a subdomain with all groups', function (): void {
    $set = RecordSet::fromTemplate(DomainConnectFixture::engageTemplate(), Zone::of('acme.example', 'mail'), ENGAGE_VARS);

    expect($set->toArray())->toBe([
        ['type' => 'MX', 'name' => 'send.mail.acme.example', 'value' => 'feedback-smtp.eu-west-1.amazonses.com', 'priority' => 10, 'ttl' => 3600, 'groupId' => 'sending'],
        ['type' => 'SPFM', 'name' => 'send.mail.acme.example', 'value' => 'include:amazonses.com', 'priority' => null, 'ttl' => null, 'groupId' => 'sending'],
        ['type' => 'TXT', 'name' => 'resend._domainkey.mail.acme.example', 'value' => 'p=MIGf', 'priority' => null, 'ttl' => 3600, 'groupId' => 'sending'],
        ['type' => 'TXT', 'name' => '_dmarc.mail.acme.example', 'value' => 'v=DMARC1; p=quarantine', 'priority' => null, 'ttl' => 3600, 'groupId' => 'dmarc'],
    ]);
});

it('keeps only the requested groups', function (): void {
    $set = RecordSet::fromTemplate(DomainConnectFixture::engageTemplate(), Zone::of('acme.example', 'mail'), ENGAGE_VARS, ['sending']);

    expect($set->records)->toHaveCount(3)
        ->and(array_map(fn (ExpectedRecord $r): ?string => $r->groupId, $set->records))->each->toBe('sending');
});

it('treats @ as the zone and a trailing dot as absolute', function (): void {
    $template = DomainConnectFixture::templateWithRecords([
        ['type' => 'A', 'host' => '@', 'pointsTo' => '192.0.2.1', 'ttl' => 300],
        ['type' => 'CNAME', 'host' => 'www', 'pointsTo' => 'Edge.Cbox.Example.', 'ttl' => 300],
        ['type' => 'TXT', 'host' => 'mail.example.net.', 'data' => 'x', 'ttl' => 300],
    ]);
    $set = RecordSet::fromTemplate($template, Zone::of('acme.example'), []);

    expect(array_map(fn (ExpectedRecord $r): string => $r->name, $set->records))->toBe(['acme.example', 'www.acme.example', 'mail.example.net'])
        ->and($set->records[1]->value)->toBe('edge.cbox.example');
});

it('treats an empty host as the zone and APEXCNAME as host @', function (): void {
    $template = DomainConnectFixture::templateWithRecords([
        ['type' => 'TXT', 'host' => '', 'data' => 'x'],
        ['type' => 'APEXCNAME', 'host' => 'ignored', 'pointsTo' => 'edge.cbox.example'],
    ]);
    $set = RecordSet::fromTemplate($template, Zone::of('acme.example', 'mail'), []);

    expect($set->records[0]->name)->toBe('mail.acme.example')
        ->and($set->records[1]->name)->toBe('mail.acme.example')
        ->and($set->records[1]->type)->toBe(TemplateRecordType::APEXCNAME);
});

it('substitutes the built-in variables from the zone', function (): void {
    $template = DomainConnectFixture::templateWithRecords([
        ['type' => 'TXT', 'host' => '_dmarc', 'data' => 'v=DMARC1; p=none; rua=mailto:dmarc@%fqdn%'],
        ['type' => 'TXT', 'host' => '_x.%domain%.', 'data' => '%domain%|%host%|%fqdn%'],
    ]);

    $sub = RecordSet::fromTemplate($template, Zone::of('acme.example', 'mail'), []);
    $apex = RecordSet::fromTemplate($template, Zone::of('acme.example'), []);

    expect($sub->records[0]->value)->toBe('v=DMARC1; p=none; rua=mailto:dmarc@mail.acme.example')
        ->and($sub->records[1]->name)->toBe('_x.acme.example')
        ->and($sub->records[1]->value)->toBe('acme.example|mail|mail.acme.example')
        ->and($apex->records[1]->value)->toBe('acme.example||acme.example');
});

it('substitutes caller variables in the host and does not rescan their values', function (): void {
    $template = DomainConnectFixture::templateWithRecords([
        ['type' => 'TXT', 'host' => '%sel%._domainkey', 'data' => '%v%'],
    ]);
    $set = RecordSet::fromTemplate($template, Zone::of('acme.example', 'mail'), ['sel' => 'resend', 'v' => '%fqdn%']);

    expect($set->records[0]->name)->toBe('resend._domainkey.mail.acme.example')
        ->and($set->records[0]->value)->toBe('%fqdn%');
});

it('refuses a missing variable', function (): void {
    RecordSet::fromTemplate(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ['mx' => 'm']);
})->throws(InvalidApplyRequest::class, 'dkim');

it('refuses an unknown variable, including a built-in', function (string $key): void {
    RecordSet::fromTemplate(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), [...ENGAGE_VARS, $key => 'x']);
})->throws(InvalidApplyRequest::class)->with(['bogus', 'fqdn']);

it('refuses an unknown group', function (): void {
    RecordSet::fromTemplate(DomainConnectFixture::engageTemplate(), Zone::of('acme.example'), ENGAGE_VARS, ['nope']);
})->throws(InvalidApplyRequest::class, 'nope');

it('refuses SRV records', function (): void {
    $template = DomainConnectFixture::templateWithRecords([['type' => 'SRV', 'host' => '_sip._tcp']]);

    RecordSet::fromTemplate($template, Zone::of('acme.example'), []);
})->throws(InvalidApplyRequest::class, 'SRV');
