<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Records;

use Cbox\Dns\Dnssec\Exceptions\MalformedRdata;
use Cbox\Dns\Dnssec\Support\TypeBitmap;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed NSEC3 RR (RFC 5155 §3): like NSEC but over hashed owner names, so the
 * zone's names are not enumerable. Carries the hash algorithm, flags, iteration
 * count, salt, the next hashed owner name, and the present-type bitmap.
 */
readonly class Nsec3
{
    /**
     * @param  array<int, true>  $types  present RR type codes, keyed by code
     */
    private function __construct(
        public int $hashAlgorithm,
        public int $flags,
        public int $iterations,
        public string $salt,
        public string $nextHashedOwner,
        public array $types,
    ) {}

    /**
     * Parse from the exact on-wire NSEC3 RDATA bytes.
     */
    public static function fromRdata(string $rdata): self
    {
        if (strlen($rdata) < 5) {
            throw MalformedRdata::make('NSEC3 RDATA shorter than 5 octets');
        }

        $hashAlgorithm = ord($rdata[0]);
        $flags = ord($rdata[1]);
        $iterations = (ord($rdata[2]) << 8) | ord($rdata[3]);
        $saltLength = ord($rdata[4]);
        $offset = 5;

        if ($offset + $saltLength > strlen($rdata)) {
            throw MalformedRdata::make('NSEC3 salt runs past end of RDATA');
        }

        $salt = substr($rdata, $offset, $saltLength);
        $offset += $saltLength;

        if ($offset >= strlen($rdata)) {
            throw MalformedRdata::make('NSEC3 missing hash-length octet');
        }

        $hashLength = ord($rdata[$offset]);
        $offset++;

        if ($hashLength < 1 || $offset + $hashLength > strlen($rdata)) {
            throw MalformedRdata::make('NSEC3 next-hashed-owner runs past end of RDATA');
        }

        $nextHashedOwner = substr($rdata, $offset, $hashLength);
        $offset += $hashLength;

        $types = TypeBitmap::parse(substr($rdata, $offset));

        return new self($hashAlgorithm, $flags, $iterations, $salt, $nextHashedOwner, $types);
    }

    /**
     * The Opt-Out flag (RFC 5155 §3.1.2.1): when set, this NSEC3 may span
     * insecure (DS-less) delegations, so absence of a name is not proven — only
     * absence of a secure delegation.
     */
    public function isOptOut(): bool
    {
        return ($this->flags & 0x01) !== 0;
    }

    public function hasType(RecordType $type): bool
    {
        return isset($this->types[$type->code()]);
    }

    public function hasTypeCode(int $code): bool
    {
        return isset($this->types[$code]);
    }
}
