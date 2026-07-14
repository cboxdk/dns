<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed CERT record (RFC 4398) — a certificate (or related object) stored in DNS.
 * Fields: the certificate type, a key tag, the algorithm, and the certificate data.
 */
readonly class Cert implements RecordData
{
    /**
     * @param  string  $certificate  the certificate data, base64-encoded
     */
    public function __construct(
        public int $certificateType,
        public int $keyTag,
        public int $algorithm,
        public string $certificate,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::CERT || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 5) {
            return null;
        }

        $certificateType = (ord($raw[0]) << 8) | ord($raw[1]);
        $keyTag = (ord($raw[2]) << 8) | ord($raw[3]);
        $algorithm = ord($raw[4]);

        return new self($certificateType, $keyTag, $algorithm, base64_encode(substr($raw, 5)));
    }

    public function presentation(): string
    {
        return "{$this->certificateType} {$this->keyTag} {$this->algorithm} {$this->certificate}";
    }
}
