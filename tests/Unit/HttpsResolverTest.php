<?php

declare(strict_types=1);

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Resolvers\HttpsResolver;

// A canned Google-DoH JSON body for `example.com TXT`: two TXT answers, one an SPF
// string, one a verification token — DoH renders each as a quoted character-string.
// AD=true here models a DNSSEC-authenticated response from the provider.
const GOOGLE_DOH_TXT = <<<'JSON'
{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": true,
  "CD": false,
  "Question": [{ "name": "example.com.", "type": 16 }],
  "Answer": [
    { "name": "example.com.", "type": 16, "TTL": 300, "data": "\"v=spf1 -all\"" },
    { "name": "example.com.", "type": 16, "TTL": 300, "data": "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\"" }
  ]
}
JSON;

// A canned Google-DoH JSON body for `example.com A`: a CNAME row rides along and
// must be filtered out, leaving only the requested A records.
const GOOGLE_DOH_A = <<<'JSON'
{
  "Status": 0,
  "AD": false,
  "Answer": [
    { "name": "example.com.", "type": 5, "TTL": 60, "data": "cdn.example.net." },
    { "name": "cdn.example.net.", "type": 1, "TTL": 60, "data": "93.184.216.34" },
    { "name": "cdn.example.net.", "type": 1, "TTL": 60, "data": "93.184.216.35" }
  ]
}
JSON;

/**
 * A fetcher that returns canned JSON and records the URL it was asked for — no
 * network. Mirrors the `callable(string): ?string` seam HttpsResolver accepts.
 */
function fakeFetcher(string $json, ?string &$captured = null): callable
{
    return function (string $url) use ($json, &$captured): ?string {
        $captured = $url;

        return $json;
    };
}

it('maps a Google-DoH TXT body to records, dequoting and joining', function (): void {
    $captured = null;
    $resolver = new HttpsResolver(HttpsResolver::GOOGLE, fakeFetcher(GOOGLE_DOH_TXT, $captured));

    $response = $resolver->query('example.com', RecordType::TXT);

    expect($response->type)->toBe(RecordType::TXT)
        ->and($response->host)->toBe('example.com')
        ->and($response->authoritative)->toBeFalse()            // DoH is a recursive view
        ->and($response->authenticated)->toBeTrue()             // AD flag captured
        ->and($response->values())->toBe(['v=spf1 -all', '_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9'])
        ->and($captured)->toContain('name=example.com')
        ->and($captured)->toContain('type=TXT');
});

it('filters a chained DoH A response down to the requested type', function (): void {
    $resolver = new HttpsResolver(HttpsResolver::GOOGLE, fakeFetcher(GOOGLE_DOH_A));

    $response = $resolver->query('example.com', RecordType::A);

    // The CNAME row (type 5) is dropped; only the two A records remain.
    expect($response->values())->toBe(['93.184.216.34', '93.184.216.35'])
        ->and($response->authenticated)->toBeFalse()
        ->and($response->records[0]->ttl)->toBe(60);
});

it('targets the Cloudflare endpoint when constructed with it', function (): void {
    $captured = null;
    $resolver = new HttpsResolver(HttpsResolver::CLOUDFLARE, fakeFetcher(GOOGLE_DOH_A, $captured));

    $resolver->query('example.com', RecordType::A);

    expect($captured)->toStartWith('https://cloudflare-dns.com/dns-query?');
});

it('throws ResolutionFailed when the fetcher returns null', function (): void {
    $resolver = new HttpsResolver(HttpsResolver::GOOGLE, fn (string $url): ?string => null);

    $resolver->query('example.com', RecordType::A);
})->throws(ResolutionFailed::class);

it('throws ResolutionFailed on malformed JSON', function (): void {
    $resolver = new HttpsResolver(HttpsResolver::GOOGLE, fn (string $url): ?string => 'not json');

    $resolver->query('example.com', RecordType::A);
})->throws(ResolutionFailed::class);

it('returns an empty response when there are no answers', function (): void {
    $resolver = new HttpsResolver(HttpsResolver::GOOGLE, fn (string $url): ?string => '{"Status":3}');

    expect($resolver->query('nope.example', RecordType::A)->isEmpty())->toBeTrue();
});
