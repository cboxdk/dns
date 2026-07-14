<?php

declare(strict_types=1);

use Cbox\Dns\Support\Hostname;

it('passes an ASCII name through unchanged and strips the trailing dot', function (): void {
    expect(Hostname::toAscii('Example.COM.'))->toBe('Example.COM');
});

it('punycodes an internationalized (IDN) name', function (): void {
    $ascii = Hostname::toAscii('blåbærgrød.dk');

    expect($ascii)->toStartWith('xn--')
        ->and($ascii)->toEndWith('.dk')
        ->and($ascii)->toBe(rtrim((string) idn_to_ascii('blåbærgrød.dk', IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46), '.'));
})->skip(! function_exists('idn_to_ascii'), 'ext-intl not installed');

it('punycodes only the non-ASCII labels, preserving an underscore challenge/service label', function (): void {
    expect(Hostname::toAscii('_cbox-challenge.münchen.de'))->toBe('_cbox-challenge.xn--mnchen-3ya.de');
})->skip(! function_exists('idn_to_ascii'), 'ext-intl not installed');

it('returns the empty root name untouched', function (): void {
    expect(Hostname::toAscii(''))->toBe('');
});
