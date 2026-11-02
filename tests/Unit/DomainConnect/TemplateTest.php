<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\Enums\Essential;
use Cbox\Dns\DomainConnect\Enums\TemplateRecordType;
use Cbox\Dns\DomainConnect\Enums\TxtConflictMatchingMode;
use Cbox\Dns\DomainConnect\Exceptions\InvalidTemplate;
use Cbox\Dns\DomainConnect\Template;
use Cbox\Dns\DomainConnect\TemplateRecord;

function engageTemplateJson(): string
{
    $json = file_get_contents(__DIR__.'/../../Fixtures/domain-connect/cbox.dk.engage-sending.json');

    return $json === false ? '' : $json;
}

it('round-trips the engage-sending template through fromJson and toArray', function (): void {
    $json = engageTemplateJson();
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
    $template = Template::fromJson(engageTemplateJson());

    expect($template->variables())->toBe(['mx', 'dkim'])
        ->and($template->groupIds())->toBe(['sending', 'dmarc']);
});

it('refuses a template without the required fields or with an unknown record type', function (): void {
    expect(fn () => Template::fromArray(['providerId' => 'x']))->toThrow(InvalidTemplate::class);
    expect(fn () => TemplateRecord::fromArray(['type' => 'PTR', 'host' => '@']))->toThrow(InvalidTemplate::class);
});

it('refuses wrongly typed fields and malformed json', function (): void {
    $base = json_decode(engageTemplateJson(), true);

    expect(fn () => Template::fromArray([...$base, 'version' => '1']))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'records' => 'nope']))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'records' => ['nope']]))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromArray([...$base, 'providerName' => 5]))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromJson('{not json'))->toThrow(InvalidTemplate::class);
    expect(fn () => Template::fromJson('"str"'))->toThrow(InvalidTemplate::class);
});
