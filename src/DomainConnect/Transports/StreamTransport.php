<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Transports;

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use Closure;

class StreamTransport implements Transport
{
    /** @var Closure(string, array<string, array<string, mixed>>): HttpResponse */
    private Closure $fetcher;

    /**
     * The fetcher receives the final URL and its stream-context options; a
     * custom one replaces the network fetch, for tests.
     *
     * @param  (callable(string, array<string, array<string, mixed>>): HttpResponse)|null  $fetcher
     */
    public function __construct(
        private readonly float $timeout = 5.0,
        ?callable $fetcher = null,
    ) {
        $this->fetcher = $fetcher !== null ? Closure::fromCallable($fetcher) : self::defaultFetcher();
    }

    public function get(string $url, ?string $resolvedIp = null): HttpResponse
    {
        $options = [
            'http' => [
                'method' => 'GET',
                'header' => "User-Agent: cboxdk/dns\r\nAccept: application/json\r\n",
                'timeout' => $this->timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
        ];

        if ($resolvedIp !== null) {
            $parts = parse_url($url);
            $host = is_array($parts) ? ($parts['host'] ?? null) : null;

            if ($host === null) {
                return new HttpResponse(0, '');
            }

            $port = isset($parts['port']) ? ":{$parts['port']}" : '';
            $peer = str_contains($resolvedIp, ':') ? "[{$resolvedIp}]" : $resolvedIp;
            $bareHost = trim($host, '[]');

            $url = ($parts['scheme'] ?? 'https').'://'.$peer.$port
                .($parts['path'] ?? '')
                .(isset($parts['query']) ? "?{$parts['query']}" : '');
            $options['http']['header'] = "Host: {$host}{$port}\r\n".$options['http']['header'];
            $options['ssl'] = ['peer_name' => $bareHost, 'verify_peer' => true, 'verify_peer_name' => true];
        }

        return ($this->fetcher)($url, $options);
    }

    /**
     * @return Closure(string, array<string, array<string, mixed>>): HttpResponse
     */
    private static function defaultFetcher(): Closure
    {
        return static function (string $url, array $options): HttpResponse {
            $body = @file_get_contents($url, false, stream_context_create($options));
            $headers = http_get_last_response_headers();

            if ($body === false || $headers === null || $headers === []) {
                return new HttpResponse(0, '');
            }

            $status = preg_match('#^HTTP/\S+\s+(\d{3})#', $headers[0], $m) === 1 ? (int) $m[1] : 0;

            return new HttpResponse($status, $body);
        };
    }
}
