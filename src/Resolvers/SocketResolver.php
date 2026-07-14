<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\ConcurrentResolver;
use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\Rcode;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Exceptions\MalformedMessage;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Protocol\Encoder;
use Cbox\Dns\Support\Hostname;
use Cbox\Dns\ValueObjects\DnsResponse;
use Cbox\Dns\ValueObjects\QueryRequest;

/**
 * The zero-dependency raw resolver: it speaks DNS over UDP sockets directly (with
 * a TCP retry when the answer is truncated), so it can target any nameserver —
 * including a zone's authoritative servers — without a recursive resolver or an
 * external `dig` binary in between.
 *
 * Spoofing resistance: every response is accepted only if its transaction ID and
 * echoed question (name + type) match the query exactly (see {@see Decoder::decode()});
 * a mismatched datagram is rejected as malformed rather than trusted. Enabling
 * `$zeroX20` additionally randomises the query name's letter case and requires an
 * exact-case echo, for extra entropy against spoofers — off by default because a
 * minority of authoritative servers normalise case and would then be unreachable.
 * A lost UDP datagram is retried up to `$attempts` times before the query fails.
 */
class SocketResolver implements ConcurrentResolver, Resolver
{
    /** Max UDP sockets open at once in a concurrent batch, to bound file-descriptor use. */
    private const int MAX_CONCURRENT_SOCKETS = 64;

    public function __construct(
        private readonly string $defaultNameserver = '1.1.1.1',
        private readonly float $timeout = 3.0,
        private readonly int $attempts = 2,
        private readonly bool $zeroX20 = false,
        private readonly Encoder $encoder = new Encoder,
        private readonly Decoder $decoder = new Decoder,
    ) {}

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
    {
        $nameserver ??= $this->defaultNameserver;
        $ascii = Hostname::toAscii($host);
        $lastFailure = ResolutionFailed::make($nameserver, 'no attempt made');

        // Each attempt gets a FRESH transaction ID (and 0x20 casing), so a single
        // injected/spoofed datagram — rejected by ID/question validation as a
        // MalformedMessage — costs one retry rather than denying the real answer.
        for ($attempt = 0; $attempt < max(1, $this->attempts); $attempt++) {
            $id = random_int(0, 0xFFFF);
            $qname = $this->zeroX20 ? $this->applyZeroX20($ascii) : $ascii;
            $message = $this->encoder->query($qname, $type, $recursion, $id, $dnssec);

            try {
                $response = $this->transceive($nameserver, $message);
                $decoded = $this->decoder->decode($response, $type, $qname, expectedId: $id, strictCase: $this->zeroX20);

                return new DnsResponse(
                    $decoded->type,
                    $ascii,
                    $decoded->records,
                    $nameserver,
                    $decoded->authoritative,
                    $decoded->authenticated,
                    $decoded->answer,
                    $decoded->authority,
                    $decoded->rcode,
                );
            } catch (ResolutionFailed|MalformedMessage $failure) {
                $lastFailure = $failure;
            }
        }

        throw $lastFailure;
    }

    /**
     * Resolve a batch of queries concurrently: all UDP datagrams are sent up front
     * and their replies collected with a single shared timeout budget, so a panel
     * of N nameservers costs one timeout rather than N. Order is preserved; a probe
     * that fails or times out yields an empty {@see DnsResponse} (records `[]`,
     * ServFail) so a caller can read every slot uniformly.
     *
     * @param  list<QueryRequest>  $requests
     * @return list<DnsResponse>
     */
    public function queryConcurrently(array $requests): array
    {
        $results = [];

        // Cap the number of sockets open at once so a huge batch cannot exhaust file
        // descriptors — process it in chunks, each chunk sharing one timeout budget.
        foreach (array_chunk($requests, self::MAX_CONCURRENT_SOCKETS) as $chunk) {
            foreach ($this->resolveChunk($chunk) as $response) {
                $results[] = $response;
            }
        }

        return $results;
    }

    /**
     * @param  list<QueryRequest>  $requests
     * @return list<DnsResponse>
     */
    private function resolveChunk(array $requests): array
    {
        if ($requests === []) {
            return [];
        }

        /** @var array<int, array{socket: resource, request: QueryRequest, id: int, qname: string, type: RecordType, message: string}> $pending */
        $pending = [];
        $results = [];

        foreach ($requests as $i => $request) {
            $results[$i] = $this->emptyResponse($request);

            try {
                $ascii = Hostname::toAscii($request->host);
                $id = random_int(0, 0xFFFF);
                $qname = $this->zeroX20 ? $this->applyZeroX20($ascii) : $ascii;
                $message = $this->encoder->query($qname, $request->type, $request->recursion, $id, $request->dnssec);
                $nameserver = $request->nameserver ?? $this->defaultNameserver;
                $socket = $this->connect('udp://'.$this->wrap($nameserver).':53');
                fwrite($socket, $message);
                $pending[$i] = compact('socket', 'request', 'id', 'qname', 'message') + ['type' => $request->type];
            } catch (DnsException) {
                unset($pending[$i]);
            }
        }

        try {
            $this->collect($pending, $results);
        } finally {
            foreach ($pending as $entry) {
                fclose($entry['socket']);
            }
        }

        return array_values($results);
    }

    /**
     * A single UDP exchange, falling back to TCP on a truncated answer. Retries and
     * response validation are owned by {@see self::query()}, which loops over this.
     */
    private function transceive(string $nameserver, string $message): string
    {
        $response = $this->overUdp($nameserver, $message);

        return Decoder::isTruncated($response)
            ? $this->overTcp($nameserver, $message)
            : $response;
    }

    private function overUdp(string $nameserver, string $message): string
    {
        $socket = $this->connect('udp://'.$this->wrap($nameserver).':53');

        fwrite($socket, $message);
        $response = fread($socket, 4096);
        $timedOut = stream_get_meta_data($socket)['timed_out'];
        fclose($socket);

        if ($timedOut === true) {
            throw ResolutionFailed::make($nameserver, 'timed out');
        }

        if (! is_string($response) || $response === '') {
            throw ResolutionFailed::make($nameserver, 'no response');
        }

        return $response;
    }

    private function overTcp(string $nameserver, string $message): string
    {
        $socket = $this->connect('tcp://'.$this->wrap($nameserver).':53');

        // TCP DNS frames the message with a 2-byte length prefix (RFC 1035 §4.2.2).
        fwrite($socket, pack('n', strlen($message)).$message);

        $lengthPrefix = fread($socket, 2);

        if (! is_string($lengthPrefix) || strlen($lengthPrefix) < 2) {
            fclose($socket);
            throw ResolutionFailed::make($nameserver, 'short TCP response');
        }

        $length = (ord($lengthPrefix[0]) << 8) | ord($lengthPrefix[1]);
        $response = '';

        while (strlen($response) < $length) {
            $chunk = fread($socket, max(1, $length - strlen($response)));

            if (! is_string($chunk) || $chunk === '') {
                break;
            }

            $response .= $chunk;
        }

        fclose($socket);

        if (strlen($response) < $length) {
            throw ResolutionFailed::make($nameserver, 'truncated TCP response');
        }

        return $response;
    }

    /**
     * @return resource
     */
    private function connect(string $address)
    {
        $socket = @stream_socket_client($address, $errno, $errstr, $this->timeout);

        if ($socket === false) {
            throw ResolutionFailed::make($address, is_string($errstr) && $errstr !== '' ? $errstr : 'connection failed');
        }

        stream_set_timeout($socket, (int) $this->timeout, (int) (fmod($this->timeout, 1) * 1_000_000));

        return $socket;
    }

    /**
     * Read replies for every still-pending concurrent probe, up to the shared
     * timeout budget, decoding and validating each into its result slot. A probe
     * whose datagram is truncated falls back to a (blocking) TCP exchange.
     *
     * @param  array<int, array{socket: resource, request: QueryRequest, id: int, qname: string, type: RecordType, message: string}>  $pending
     * @param  array<int, DnsResponse>  $results
     */
    private function collect(array $pending, array &$results): void
    {
        $deadline = $this->monotonicDeadline();

        while ($pending !== []) {
            $remaining = $deadline - $this->now();

            if ($remaining <= 0) {
                break;
            }

            $read = array_map(static fn (array $e) => $e['socket'], $pending);
            $write = $except = [];
            $seconds = (int) $remaining;
            $micro = (int) (($remaining - $seconds) * 1_000_000);

            $ready = @stream_select($read, $write, $except, $seconds, $micro);

            if ($ready === false) {
                continue; // interrupted (EINTR); retry while the budget remains
            }

            if ($ready === 0) {
                break; // budget exhausted with no ready socket
            }

            foreach ($read as $socket) {
                $i = $this->indexOfSocket($pending, $socket);

                if ($i === null) {
                    continue;
                }

                $entry = $pending[$i];
                unset($pending[$i]);

                $raw = fread($socket, 4096);

                if (! is_string($raw) || $raw === '') {
                    continue;
                }

                try {
                    if (Decoder::isTruncated($raw)) {
                        $nameserver = $entry['request']->nameserver ?? $this->defaultNameserver;
                        $raw = $this->overTcp($nameserver, $entry['message']);
                    }

                    $decoded = $this->decoder->decode($raw, $entry['type'], $entry['qname'], expectedId: $entry['id'], strictCase: $this->zeroX20);
                    $results[$i] = new DnsResponse(
                        $decoded->type,
                        Hostname::toAscii($entry['request']->host),
                        $decoded->records,
                        $entry['request']->nameserver ?? $this->defaultNameserver,
                        $decoded->authoritative,
                        $decoded->authenticated,
                        $decoded->answer,
                        $decoded->authority,
                        $decoded->rcode,
                    );
                } catch (DnsException) {
                    // Leave the pre-seeded empty ServFail response for this slot.
                }
            }
        }
    }

    /**
     * @param  array<int, array{socket: resource, request: QueryRequest, id: int, qname: string, type: RecordType, message: string}>  $pending
     * @param  resource  $socket
     */
    private function indexOfSocket(array $pending, $socket): ?int
    {
        foreach ($pending as $i => $entry) {
            if ($entry['socket'] === $socket) {
                return $i;
            }
        }

        return null;
    }

    private function emptyResponse(QueryRequest $request): DnsResponse
    {
        return new DnsResponse(
            $request->type,
            rtrim($request->host, '.'),
            [],
            $request->nameserver,
            rcode: Rcode::ServFail,
        );
    }

    /**
     * Bracket a bare IPv6 literal for a `stream_socket_client` address; IPv4 and
     * hostnames pass through unchanged (RFC 3986 §3.2.2).
     */
    private function wrap(string $nameserver): string
    {
        return str_contains($nameserver, ':') && ! str_contains($nameserver, '[')
            ? '['.$nameserver.']'
            : $nameserver;
    }

    /**
     * Apply 0x20 encoding (draft-vixie-dnsext-dns0x20): randomise the case of each
     * ASCII letter in the query name. The authoritative server echoes the question
     * verbatim, so the mixed-case pattern becomes ~extra entropy a spoofer must also
     * guess on top of the transaction ID and source port.
     */
    private function applyZeroX20(string $host): string
    {
        $out = '';

        foreach (str_split($host) as $char) {
            $out .= match (true) {
                ctype_alpha($char) && random_int(0, 1) === 1 => strtoupper($char) === $char ? strtolower($char) : strtoupper($char),
                default => $char,
            };
        }

        return $out;
    }

    private function monotonicDeadline(): float
    {
        return $this->now() + $this->timeout;
    }

    private function now(): float
    {
        return (float) hrtime(true) / 1_000_000_000;
    }
}
