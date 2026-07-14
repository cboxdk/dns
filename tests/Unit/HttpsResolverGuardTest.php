<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Resolvers\HttpsResolver;

it('refuses to target a specific nameserver — DoH cannot answer authoritatively', function (): void {
    $resolver = new HttpsResolver(fetcher: fn () => '{"Status":0}');

    $resolver->query('example.com', RecordType::A, '8.8.8.8');
})->throws(ResolutionFailed::class, 'target a specific nameserver');

it('refuses a non-recursive query', function (): void {
    $resolver = new HttpsResolver(fetcher: fn () => '{"Status":0}');

    $resolver->query('example.com', RecordType::A, recursion: false);
})->throws(ResolutionFailed::class, 'non-recursively');

it('surfaces the DoH Status as an RCODE', function (): void {
    $resolver = new HttpsResolver(fetcher: fn () => '{"Status":3}');

    expect($resolver->query('nope.example.com', RecordType::A)->isNxDomain())->toBeTrue();
});
