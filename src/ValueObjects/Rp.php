<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Support\RawName;

/**
 * A parsed RP record (RFC 1183 §2.2) — the Responsible Person for a name: a mailbox
 * (as a domain name, with the `@` written as the first label's dot) and the name of
 * a TXT record with more contact information.
 */
readonly class Rp implements RecordData
{
    public function __construct(
        public string $mailbox,
        public string $txtDomain,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::RP || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        $offset = 0;
        $mailbox = RawName::read($raw, $offset);
        $txtDomain = RawName::read($raw, $offset);

        if ($mailbox === null || $txtDomain === null) {
            return null;
        }

        return new self($mailbox, $txtDomain);
    }

    public function presentation(): string
    {
        return "{$this->mailbox} {$this->txtDomain}";
    }
}
