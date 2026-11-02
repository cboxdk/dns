<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Transports;

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use Closure;

/**
 * The default {@see Transport}: a GET over PHP streams that never follows a
 * redirect, honours a pinned address (connecting to it while verifying TLS for the
 * URL's host), stops after `$timeout` seconds in total and refuses a response body
 * over 64 KiB.
 */
class StreamTransport implements Transport
{
    /** Bodies larger than this are refused (status 0), not truncated. */
    public const int MAX_BODY_BYTES = 65536;

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
        $this->fetcher = $fetcher !== null ? Closure::fromCallable($fetcher) : self::defaultFetcher($this->timeout);
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
     * The network fetch: a PHP stream that does not follow redirects, gives up
     * after `$timeout` seconds in total (connect, headers and body together), and
     * refuses — status 0, not a truncated body — a body larger than
     * {@see self::MAX_BODY_BYTES}.
     *
     * @return Closure(string, array<string, array<string, mixed>>): HttpResponse
     */
    private static function defaultFetcher(float $timeout): Closure
    {
        return static function (string $url, array $options) use ($timeout): HttpResponse {
            $deadline = microtime(true) + $timeout;
            set_error_handler(static fn (): bool => true); // a failed fetch is reported as status 0, not a warning

            try {
                $stream = fopen($url, 'r', false, stream_context_create($options));
            } finally {
                restore_error_handler();
            }

            if ($stream === false) {
                return new HttpResponse(0, '');
            }

            try {
                $headers = stream_get_meta_data($stream)['wrapper_data'] ?? null;
                $status = 0;

                foreach (is_array($headers) ? $headers : [] as $line) {
                    if (is_string($line) && preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                        $status = (int) $m[1];
                    }
                }

                $body = '';

                while (! feof($stream)) {
                    $remaining = $deadline - microtime(true);

                    if ($remaining <= 0) {
                        return new HttpResponse(0, '');
                    }

                    stream_set_timeout($stream, (int) $remaining, (int) (fmod($remaining, 1.0) * 1_000_000));
                    $chunk = fread($stream, 8192);

                    if ($chunk === false || stream_get_meta_data($stream)['timed_out']) {
                        return new HttpResponse(0, '');
                    }

                    $body .= $chunk;

                    if (strlen($body) > self::MAX_BODY_BYTES) {
                        return new HttpResponse(0, '');
                    }
                }

                return $status === 0 ? new HttpResponse(0, '') : new HttpResponse($status, $body);
            } finally {
                fclose($stream);
            }
        };
    }
}
