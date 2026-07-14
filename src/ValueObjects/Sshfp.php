<?php

declare(strict_types=1);

namespace Cbox\Dns\ValueObjects;

use Cbox\Dns\Contracts\RecordData;
use Cbox\Dns\Enums\RecordType;

/**
 * A parsed SSHFP record (RFC 4255) — an SSH host-key fingerprint published in DNS.
 * The fields are the public-key algorithm (1 = RSA, 2 = DSA, 3 = ECDSA, 4 = Ed25519),
 * the fingerprint type (1 = SHA-1, 2 = SHA-256), and the fingerprint itself.
 */
readonly class Sshfp implements RecordData
{
    /**
     * @param  string  $fingerprint  the fingerprint as lowercase hex
     */
    public function __construct(
        public int $algorithm,
        public int $fingerprintType,
        public string $fingerprint,
    ) {}

    public static function fromRecord(DnsRecord $record): ?self
    {
        if ($record->type !== RecordType::SSHFP || $record->raw === null) {
            return null;
        }

        return self::fromRdata($record->raw);
    }

    public static function fromRdata(string $raw): ?self
    {
        if (strlen($raw) < 3) {
            return null;
        }

        return new self(ord($raw[0]), ord($raw[1]), bin2hex(substr($raw, 2)));
    }

    public function presentation(): string
    {
        return "{$this->algorithm} {$this->fingerprintType} {$this->fingerprint}";
    }
}
