<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed OPENPGPKEY record (RFC 7929) — an OpenPGP public key published in DNS for
 * a given email identity. The RDATA is the raw Transferable Public Key; the
 * presentation form is its base64 encoding.
 */
readonly class Openpgpkey implements RecordData
{
    /**
     * @param  string  $publicKey  the OpenPGP public key, base64-encoded
     */
    public function __construct(
        public string $publicKey,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::OPENPGPKEY || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): self
    {
        return new self(base64_encode($raw));
    }

    public function presentation(): string
    {
        return $this->publicKey;
    }
}
