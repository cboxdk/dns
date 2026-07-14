<?php

declare(strict_types=1);

namespace Cbox\Dns\Protocol;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\InvalidName;

/**
 * Builds a raw DNS query message (RFC 1035 §4.1). A single question, class IN.
 * `recursion` sets the RD bit — off when asking an authoritative server directly,
 * on when asking a recursive resolver.
 */
final class Encoder
{
    public function query(string $host, RecordType $type, bool $recursion = true, ?int $id = null): string
    {
        $id ??= random_int(0, 0xFFFF);
        $flags = $recursion ? 0x0100 : 0x0000; // RD bit

        $header = pack('n6', $id, $flags, 1, 0, 0, 0);
        $question = $this->qname($host).pack('n2', $type->code(), 1); // QTYPE, QCLASS=IN

        return $header.$question;
    }

    /**
     * Encode a domain name as length-prefixed labels terminated by the root.
     */
    public function qname(string $host): string
    {
        $host = trim($host, '.');
        $encoded = '';

        if ($host !== '') {
            foreach (explode('.', $host) as $label) {
                $length = strlen($label);

                if ($length > 63) {
                    throw InvalidName::make($host);
                }

                $encoded .= chr($length).$label;
            }
        }

        return $encoded."\0"; // root label terminates the name
    }
}
