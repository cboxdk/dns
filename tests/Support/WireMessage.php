<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Support;

/**
 * A tiny DNS wire-message builder for decoder/resolver tests: assembles raw
 * response bytes (header, question, answer RRs) without compression, so a test can
 * craft exactly the ID, RCODE, question, and records it wants to feed the decoder.
 */
final class WireMessage
{
    /**
     * @param  list<array{name: string, type: int, rdata: string}>  $answers
     */
    public static function response(
        int $id,
        string $qname,
        int $qtype,
        array $answers = [],
        int $rcode = 0,
        bool $authoritative = true,
    ): string {
        $flags = 0x8000 | ($authoritative ? 0x0400 : 0) | ($rcode & 0x000F);

        $message = pack('n6', $id, $flags, 1, count($answers), 0, 0);
        $message .= self::name($qname).pack('n2', $qtype, 1);

        foreach ($answers as $answer) {
            $message .= self::name($answer['name'])
                .pack('n2', $answer['type'], 1)
                .pack('N', 300)
                .pack('n', strlen($answer['rdata']))
                .$answer['rdata'];
        }

        return $message;
    }

    /**
     * Encode a domain name as uncompressed length-prefixed labels + root.
     */
    public static function name(string $host): string
    {
        $host = trim($host, '.');
        $encoded = '';

        if ($host !== '') {
            foreach (explode('.', $host) as $label) {
                $encoded .= chr(strlen($label)).$label;
            }
        }

        return $encoded."\0";
    }

    /**
     * The A-record RDATA for a dotted IPv4 address.
     */
    public static function a(string $ip): string
    {
        return inet_pton($ip);
    }
}
