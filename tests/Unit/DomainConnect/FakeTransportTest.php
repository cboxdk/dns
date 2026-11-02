<?php

declare(strict_types=1);

use Cbox\Dns\DomainConnect\HttpResponse;
use Cbox\Dns\DomainConnect\Testing\FakeTransport;

it('serves stubbed responses, records requests, and refuses unknown urls when strict', function (): void {
    $fake = (new FakeTransport)->stub('https://dc.example/v2/example.com/settings', 200, ['providerId' => 'x', 'providerName' => 'X']);

    expect($fake->get('https://dc.example/v2/example.com/settings')->json())->toBe(['providerId' => 'x', 'providerName' => 'X'])
        ->and($fake->get('https://other/')->status)->toBe(0)
        ->and($fake->requests())->toBe(['https://dc.example/v2/example.com/settings', 'https://other/']);

    expect(fn () => $fake->strict()->get('https://nope/'))->toThrow(LogicException::class, 'https://nope/');
});

it('passes string bodies through verbatim and asserts requested urls', function (): void {
    $fake = (new FakeTransport)->stub('https://a/', 201, 'raw');

    $response = $fake->get('https://a/');

    expect($response->status)->toBe(201)
        ->and($response->body)->toBe('raw');
    $fake->assertRequested('https://a/');
});

it('turns a non-2xx status into ok() false and a non-JSON body into json() null', function (): void {
    expect((new HttpResponse(404, 'not found'))->ok())->toBeFalse()
        ->and((new HttpResponse(204, ''))->ok())->toBeTrue()
        ->and((new HttpResponse(200, 'not json'))->json())->toBeNull()
        ->and((new HttpResponse(200, '"scalar"'))->json())->toBeNull()
        ->and((new HttpResponse(200, '["a","b"]'))->json())->toBeNull()
        ->and((new HttpResponse(200, '{"a":1}'))->json())->toBe(['a' => 1]);
});

it('matches stubs by url regardless of the pinned address and records the pin', function (): void {
    $fake = (new FakeTransport)->strict()->stub('https://a/', 200, 'ok');

    expect($fake->get('https://a/', '203.0.113.10')->body)->toBe('ok')
        ->and($fake->requests())->toBe(['https://a/'])
        ->and($fake->pinned())->toBe(['https://a/' => '203.0.113.10']);

    $fake->get('https://a/');

    expect($fake->pinned())->toBe(['https://a/' => null]);
});
