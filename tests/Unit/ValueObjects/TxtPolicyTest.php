<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\ValueObjects\DkimKey;
use Cbox\Dns\ValueObjects\DmarcPolicy;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\SpfPolicy;
use Cbox\Dns\ValueObjects\Txt;

it('parses an SPF policy from a TXT record', function (): void {
    $txt = new Txt('v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all');
    $spf = $txt->spf();

    expect($spf)->toBeInstanceOf(SpfPolicy::class)
        ->and($spf->allQualifier)->toBe('-')
        ->and($spf->mechanisms[0]->name)->toBe('include')
        ->and($spf->mechanisms[0]->value)->toBe('_spf.google.com')
        ->and($spf->mechanisms[1]->name)->toBe('ip4')
        ->and($spf->mechanisms[2]->result())->toBe('fail');
});

it('parses an SPF redirect modifier', function (): void {
    expect((new Txt('v=spf1 redirect=_spf.example.com'))->spf()?->redirect)->toBe('_spf.example.com');
});

it('returns null SPF for a non-SPF TXT', function (): void {
    expect((new Txt('just some text'))->spf())->toBeNull();
});

it('parses a DKIM key and detects revocation and testing', function (): void {
    $dkim = (new Txt('v=DKIM1; k=rsa; t=y; p=MIGfMA0GCS'))->dkim();

    expect($dkim)->toBeInstanceOf(DkimKey::class)
        ->and($dkim->keyType)->toBe('rsa')
        ->and($dkim->publicKey)->toBe('MIGfMA0GCS')
        ->and($dkim->isTesting())->toBeTrue()
        ->and($dkim->isRevoked())->toBeFalse();

    expect((new Txt('v=DKIM1; k=rsa; p='))->dkim()?->isRevoked())->toBeTrue();
});

it('parses a DMARC policy with reporting and subdomain fallback', function (): void {
    $dmarc = (new Txt('v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s'))->dmarc();

    expect($dmarc)->toBeInstanceOf(DmarcPolicy::class)
        ->and($dmarc->policy)->toBe('reject')
        ->and($dmarc->effectiveSubdomainPolicy())->toBe('quarantine')
        ->and($dmarc->percentage)->toBe(50)
        ->and($dmarc->aggregateReports)->toBe(['mailto:a@x.com', 'mailto:b@x.com'])
        ->and($dmarc->adkim)->toBe('s');
});

it('falls back to the domain policy for subdomains when sp is absent', function (): void {
    expect((new Txt('v=DMARC1; p=reject'))->dmarc()?->effectiveSubdomainPolicy())->toBe('reject');
});

it('does not misparse SPF as DKIM or DMARC', function (): void {
    $txt = new Txt('v=spf1 -all');

    expect($txt->dkim())->toBeNull()
        ->and($txt->dmarc())->toBeNull();
});

it('reaches the policies through a record\'s typed data', function (): void {
    $record = new DnsRecord(RecordType::TXT, 'example.com', 'v=spf1 -all');
    $data = $record->data();

    expect($data)->toBeInstanceOf(Txt::class)
        ->and($data->spf())->toBeInstanceOf(SpfPolicy::class);
});
