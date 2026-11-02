<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Enums\Essential;
use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\Enums\TxtConflictMatchingMode;
use Cbox\Dns\DomainConnect\Exceptions\InvalidTemplate;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\TemplateRecord;
use Cbox\Dns\Tests\Support\DomainConnectFixture;

it('round-trips the engage-sending template through fromJson and toArray', function (): void {
    $json = DomainConnectFixture::file('cbox.dk.engage-sending.json');
    $template = Template::fromJson($json);

    expect($template->providerId)->toBe('cbox.dk')
        ->and($template->serviceId)->toBe('engage-sending')
        ->and($template->syncPubKeyDomain)->toBe('cbox.dk')
        ->and($template->syncRedirectDomain)->toBe('cboxengage.com')
        ->and($template->records)->toHaveCount(4)
        ->and($template->records[1]->type)->toBe(TemplateRecordType::SPFM)
        ->and($template->records[3]->essential)->toBe(Essential::OnApply)
        ->and($template->records[3]->txtConflictMatchingMode)->toBe(TxtConflictMatchingMode::Prefix)
        ->and($template->toArray())->toBe(json_decode($json, true));
});

it('lists the variables and group ids a template uses, in order of first appearance', function (): void {
    $template = Template::fromJson(DomainConnectFixture::file('cbox.dk.engage-sending.json'));

    expect($template->variables())->toBe(['mx', 'dkim'])
        ->and($template->groupIds())->toBe(['sending', 'dmarc']);
});

it('reads variables from the host field and leaves out the provider-supplied domain, host and fqdn', function (): void {
    $template = Template::fromArray([...Template::fromJson(DomainConnectFixture::file('cbox.dk.engage-sending.json'))->toArray(), 'records' => [
        ['type' => 'TXT', 'host' => '%sel%._domainkey', 'data' => 'p=%key%; rua=mailto:dmarc@%fqdn%', 'ttl' => 3600],
        ['type' => 'CNAME', 'host' => '%Host%', 'pointsTo' => '%DOMAIN%.example.net', 'ttl' => 3600],
    ]]);

    expect($template->variables())->toBe(['sel', 'key']);
});

it('refuses a template without the required fields or with an unknown record type', function (): void {
    expect(fn () => Template::fromArray(['providerId' => 'x']))->toThrow(InvalidTemplate::class);
    expect(fn () => TemplateRecord::fromArray(['type' => 'PTR', 'host' => '@']))->toThrow(InvalidTemplate::class);
});

it('refuses wrongly typed fields and malformed json', function (): void {
    $base = json_decode(DomainConnectFixture::file('cbox.dk.engage-sending.json'), true);

    expect(fn () => Template::fromArray([...$base, 'version' => '1']))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'records' => 'nope']))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'records' => ['nope']]))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'providerName' => 5]))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromJson('{not json'))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromJson('"str"'))->toThrow(InvalidTemplate::class);
});
