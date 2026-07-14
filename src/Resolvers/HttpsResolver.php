<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use Closure;

/**
 * A DNS-over-HTTPS (DoH) resolver speaking the JSON API shared by Google
 * (`https://dns.google/resolve`) and Cloudflare (`https://cloudflare-dns.com/dns-query`).
 * It maps the JSON `Answer[]` array to {@see DnsRecord}s of the requested type.
 *
 * DoH answers come from the provider's recursive resolver, so they are never
 * authoritative — use {@see AuthoritativeResolver} when the zone's own view is
 * required. The provider's DNSSEC-validated (`AD`) flag is surfaced on the
 * {@see DnsResponse::$authenticated} field.
 *
 * Zero runtime dependency: HTTP is performed through an injectable fetcher
 * (`callable(string $url): ?string`). The default uses `file_get_contents` with
 * a stream context; tests inject a fetcher returning canned JSON, so the suite
 * never touches the network.
 */
final class HttpsResolver implements Resolver
{
    /**
     * Google's DoH JSON endpoint (the class default).
     */
    public const string GOOGLE = 'https://dns.google/resolve';

    /**
     * Cloudflare's DoH JSON endpoint. Handy for `new HttpsResolver(HttpsResolver::CLOUDFLARE)`.
     */
    public const string CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';

    /** @var Closure(string): (string|null) */
    private readonly Closure $fetcher;

    /**
     * @param  (callable(string): (string|null))|null  $fetcher
     */
    public function __construct(
        private readonly string $endpoint = self::GOOGLE,
        ?callable $fetcher = null,
        private readonly float $timeout = 3.0,
    ) {
        $this->fetcher = $fetcher !== null
            ? Closure::fromCallable($fetcher)
            : $this->defaultFetcher();
    }

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true): DnsResponse
    {
        $host = rtrim($host, '.');
        $url = $this->endpoint.'?'.http_build_query(['name' => $host, 'type' => $type->value]);

        $body = ($this->fetcher)($url);

        if (! is_string($body) || $body === '') {
            throw ResolutionFailed::make($this->endpoint, 'no DoH response');
        }

        $decoded = json_decode($body, true);

        if (! is_array($decoded)) {
            throw ResolutionFailed::make($this->endpoint, 'malformed DoH JSON');
        }

        return new DnsResponse(
            $type,
            $host,
            $this->records($decoded, $type, $host),
            $this->endpoint,
            authoritative: false,
            authenticated: ($decoded['AD'] ?? null) === true,
        );
    }

    /**
     * @param  array<array-key, mixed>  $decoded
     * @return list<DnsRecord>
     */
    private function records(array $decoded, RecordType $type, string $host): array
    {
        $answers = $decoded['Answer'] ?? null;

        if (! is_array($answers)) {
            return [];
        }

        $records = [];

        foreach ($answers as $answer) {
            if (! is_array($answer)) {
                continue;
            }

            $answerType = $answer['type'] ?? null;

            // DoH labels answers by numeric TYPE; skip the CNAME/other rows that
            // ride along in a chained response and keep only the requested type.
            if (! is_int($answerType) || $answerType !== $type->code()) {
                continue;
            }

            $data = $answer['data'] ?? null;

            if (! is_string($data)) {
                continue;
            }

            $records[] = $this->record($type, $host, $data, $this->ttl($answer));
        }

        return $records;
    }

    /**
     * @param  array<array-key, mixed>  $answer
     */
    private function ttl(array $answer): int
    {
        $ttl = $answer['TTL'] ?? null;

        return is_int($ttl) ? $ttl : 0;
    }

    private function record(RecordType $type, string $host, string $data, int $ttl): DnsRecord
    {
        $priority = null;
        $value = match ($type) {
            RecordType::TXT => $this->txt($data),
            RecordType::CNAME, RecordType::NS, RecordType::PTR => rtrim($data, '.'),
            RecordType::MX => $this->mx($data, $priority),
            RecordType::SRV => $this->srv($data, $priority),
            default => rtrim($data, '.'),
        };

        return new DnsRecord($type, $host, $value, $ttl, $priority);
    }

    /**
     * DoH renders a TXT RR in presentation form: one or more double-quoted
     * character-strings separated by spaces. Concatenate the quoted segments
     * (RFC 1035 §3.3.14) after unescaping, matching the socket decoder's output.
     */
    private function txt(string $data): string
    {
        if (preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $data, $matches) > 0) {
            return implode('', array_map(stripcslashes(...), $matches[1]));
        }

        return trim($data, '"');
    }

    private function mx(string $data, ?int &$priority): string
    {
        [$pref, $exchange] = array_pad(explode(' ', trim($data), 2), 2, '');
        $priority = is_numeric($pref) ? (int) $pref : null;

        return rtrim($exchange, '.');
    }

    private function srv(string $data, ?int &$priority): string
    {
        $parts = explode(' ', trim($data));
        $priority = is_numeric($parts[0]) ? (int) $parts[0] : null;
        $weight = $parts[1] ?? '0';
        $port = $parts[2] ?? '0';
        $target = rtrim($parts[3] ?? '', '.');

        return trim("{$weight} {$port} {$target}");
    }

    /**
     * @return Closure(string): (string|null)
     */
    private function defaultFetcher(): Closure
    {
        $timeout = $this->timeout;

        return static function (string $url) use ($timeout): ?string {
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => "Accept: application/dns-json\r\n",
                    'timeout' => $timeout,
                    'ignore_errors' => true,
                ],
            ]);

            $body = @file_get_contents($url, false, $context);

            return is_string($body) ? $body : null;
        };
    }
}
