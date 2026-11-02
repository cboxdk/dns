<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Transports;

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use Closure;

class StreamTransport implements Transport
{
    /** @var Closure(string): HttpResponse */
    private Closure $fetcher;

    /**
     * @param  (callable(string): HttpResponse)|null  $fetcher  replaces the whole fetch; for tests
     */
    public function __construct(
        private readonly float $timeout = 5.0,
        ?callable $fetcher = null,
    ) {
        $this->fetcher = $fetcher !== null ? Closure::fromCallable($fetcher) : $this->defaultFetcher();
    }

    public function get(string $url): HttpResponse
    {
        return ($this->fetcher)($url);
    }

    /**
     * @return Closure(string): HttpResponse
     */
    private function defaultFetcher(): Closure
    {
        $timeout = $this->timeout;

        return static function (string $url) use ($timeout): HttpResponse {
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => "User-Agent: cboxdk/dns\r\nAccept: application/json\r\n",
                    'timeout' => $timeout,
                    'ignore_errors' => true,
                    'follow_location' => 0,
                ],
            ]);

            $body = @file_get_contents($url, false, $context);
            $headers = http_get_last_response_headers();

            if ($body === false || $headers === null || $headers === []) {
                return new HttpResponse(0, '');
            }

            $status = preg_match('#^HTTP/\S+\s+(\d{3})#', $headers[0], $m) === 1 ? (int) $m[1] : 0;

            return new HttpResponse($status, $body);
        };
    }
}
