<?php

declare(strict_types=1);

namespace Cbox\Dns\Resolvers;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\ResolutionFailed;
use Cbox\Dns\Protocol\Decoder;
use Cbox\Dns\Protocol\Encoder;
use Cbox\Dns\ValueObjects\DnsResponse;

/**
 * The zero-dependency raw resolver: it speaks DNS over UDP sockets directly (with
 * a TCP retry when the answer is truncated), so it can target any nameserver —
 * including a zone's authoritative servers — without a recursive resolver or an
 * external `dig` binary in between.
 */
final class SocketResolver implements Resolver
{
    public function __construct(
        private readonly string $defaultNameserver = '1.1.1.1',
        private readonly float $timeout = 3.0,
        private readonly Encoder $encoder = new Encoder,
        private readonly Decoder $decoder = new Decoder,
    ) {}

    public function query(string $host, RecordType $type, ?string $nameserver = null, bool $recursion = true, bool $dnssec = false): DnsResponse
    {
        $nameserver ??= $this->defaultNameserver;
        $id = random_int(0, 0xFFFF);
        $message = $this->encoder->query($host, $type, $recursion, $id, $dnssec);

        $response = $this->overUdp($nameserver, $message);

        if (Decoder::isTruncated($response)) {
            $response = $this->overTcp($nameserver, $message);
        }

        $decoded = $this->decoder->decode($response, $type, rtrim($host, '.'));

        return new DnsResponse(
            $decoded->type,
            $decoded->host,
            $decoded->records,
            $nameserver,
            $decoded->authoritative,
            $decoded->authenticated,
            $decoded->answer,
            $decoded->authority,
        );
    }

    private function overUdp(string $nameserver, string $message): string
    {
        $socket = $this->connect('udp://'.$nameserver.':53');

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
        $socket = $this->connect('tcp://'.$nameserver.':53');

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
}
