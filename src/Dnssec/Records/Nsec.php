<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec\Records;

use Cbox\Dns\Dnssec\Support\TypeBitmap;
use Cbox\Dns\Dnssec\Support\WireName;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed NSEC RR (RFC 4034 §4): the authenticated assertion that between this
 * owner name and {@see $nextDomainName} no other name exists, and that this owner
 * has exactly the RR types in {@see $types}.
 */
final readonly class Nsec
{
    /**
     * @param  array<int, true>  $types  present RR type codes, keyed by code
     */
    private function __construct(
        public string $nextDomainName,
        public array $types,
    ) {}

    /**
     * Parse from the exact on-wire NSEC RDATA bytes. The next-domain name is an
     * uncompressed wire name and is NOT down-cased (RFC 6840 §5.1).
     */
    public static function fromRdata(string $rdata): self
    {
        [$next, $offset] = WireName::read($rdata, 0);

        $types = TypeBitmap::parse(substr($rdata, $offset));

        return new self($next, $types);
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
