<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Support\Hostname;
use Cbox\Dns\ValueObjects\Cert;
use Cbox\Dns\ValueObjects\DnsRecord;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\Loc;
use Cbox\Dns\ValueObjects\Naptr;
use Cbox\Dns\ValueObjects\Openpgpkey;
use Cbox\Dns\ValueObjects\Smimea;
use Cbox\Dns\ValueObjects\Sshfp;
use Cbox\Dns\ValueObjects\Svcb;
use Cbox\Dns\ValueObjects\Tlsa;
use Cbox\Dns\ValueObjects\Uri;
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
class HttpsResolver implements Resolver
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

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
    {
        // DoH answers always come from the provider's own recursive resolver. It
        // cannot target a specific nameserver or answer non-recursively, so rather
        // than silently ignore those parameters (and return a misleading answer for
        // an authoritative/propagation probe), refuse them loudly.
        if ($nameserver !== null) {
            throw ResolutionFailed::make($this->endpoint, 'DoH cannot target a specific nameserver — use SocketResolver for authoritative queries');
        }

        if ($recursion === false) {
            throw ResolutionFailed::make($this->endpoint, 'DoH cannot answer non-recursively');
        }

        $host = Hostname::toAscii($host);
        $query = ['name' => $host, 'type' => $type->value];

        if ($dnssec) {
            // The Google/Cloudflare JSON API takes `do=1` to request DNSSEC data.
            $query['do'] = '1';
        }

        $url = $this->endpoint.'?'.http_build_query($query);

        $body = ($this->fetcher)($url);

        if (! is_string($body) || $body === '') {
            throw ResolutionFailed::make($this->endpoint, 'no DoH response');
        }

        $decoded = json_decode($body, true);

        if (! is_array($decoded)) {
            throw ResolutionFailed::make($this->endpoint, 'malformed DoH JSON');
        }

        $status = $decoded['Status'] ?? 0;

        return new DnsResponse(
            $type,
            $host,
            $this->records($decoded, $type, $host),
            $this->endpoint,
            authoritative: false,
            authenticated: ($decoded['AD'] ?? null) === true,
            rcode: Rcode::fromCode(is_int($status) ? $status : 0),
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
        $raw = null;
        $value = match ($type) {
            RecordType::TXT => $this->txt($data),
            RecordType::CNAME, RecordType::NS, RecordType::PTR => rtrim($data, '.'),
            RecordType::MX => $this->mx($data, $priority),
            RecordType::SRV => $this->srv($data, $priority),
            RecordType::NAPTR, RecordType::TLSA, RecordType::SMIMEA, RecordType::SSHFP,
            RecordType::CERT, RecordType::LOC, RecordType::OPENPGPKEY, RecordType::URI,
            RecordType::SVCB, RecordType::HTTPS => $this->exotic($type, $data, $priority, $raw),
            default => rtrim($data, '.'),
        };

        return new DnsRecord($type, $host, $value, $ttl, $priority, $raw);
    }

    /**
     * Normalise a compound record from a DoH answer. When the provider returns the
     * RFC 3597 generic form (`\# <len> <hex>`) — as some do for these types —
     * decode the wire bytes and run them through the same value object the socket
     * decoder uses, so the presentation and the attached raw RDATA match across
     * transports. Otherwise the provider's own presentation string is kept as-is.
     */
    private function exotic(RecordType $type, string $data, ?int &$priority, ?string &$raw): string
    {
        if (preg_match('/^\\\\#\s+\d+\s+([0-9a-fA-F\s]*)$/', trim($data), $m)) {
            $hex = preg_replace('/\s+/', '', $m[1]) ?? '';
            $decoded = @hex2bin($hex);

            if (is_string($decoded)) {
                $raw = $decoded;
                $value = $this->exoticPresentation($type, $decoded, $priority);

                if ($value !== null) {
                    return $value;
                }
            }
        }

        return trim($data);
    }

    /**
     * The presentation of a compound record's wire bytes via its value object,
     * carrying the priority out for the types that have one.
     */
    private function exoticPresentation(RecordType $type, string $raw, ?int &$priority): ?string
    {
        return match ($type) {
            RecordType::TLSA => Tlsa::fromRdata($raw)?->presentation(),
            RecordType::SMIMEA => Smimea::fromRdata($raw)?->presentation(),
            RecordType::SSHFP => Sshfp::fromRdata($raw)?->presentation(),
            RecordType::CERT => Cert::fromRdata($raw)?->presentation(),
            RecordType::LOC => Loc::fromRdata($raw)?->presentation(),
            RecordType::OPENPGPKEY => Openpgpkey::fromRdata($raw)->presentation(),
            RecordType::NAPTR => (function () use ($raw, &$priority): ?string {
                $naptr = Naptr::fromRdata($raw);
                $priority = $naptr?->order;

                return $naptr?->presentation();
            })(),
            RecordType::URI => (function () use ($raw, &$priority): ?string {
                $uri = Uri::fromRdata($raw);
                $priority = $uri?->priority;

                return $uri?->presentation();
            })(),
            default => (function () use ($raw, &$priority): ?string {
                $svcb = Svcb::fromRdata($raw);
                $priority = $svcb?->priority;

                return $svcb?->presentation();
            })(),
        };
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
