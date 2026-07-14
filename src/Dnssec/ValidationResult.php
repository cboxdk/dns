<?php

declare(strict_types=1);

namespace Cbox\Dns\Dnssec;

use Cbox\Dns\Dnssec\Enums\ValidationStatus;
use Cbox\Dns\Dnssec\Records\Dnskey;

/**
 * The outcome of a DNSSEC validation: the RFC 4033 security state, the target it
 * concerns, and a human-readable reason. When the zone validated Secure it also
 * carries the trusted DNSKEY set, so a follow-on record validation can reuse it.
 */
readonly class ValidationResult
{
    /**
     * @param  list<Dnskey>  $dnskeys  the validated zone keys (only for Secure)
     */
    public function __construct(
        public ValidationStatus $status,
        public string $target,
        public string $reason,
        public array $dnskeys = [],
    ) {}

    /**
     * @param  list<Dnskey>  $dnskeys
     */
    public static function secure(string $target, string $reason, array $dnskeys = []): self
    {
        return new self(ValidationStatus::Secure, $target, $reason, $dnskeys);
    }

    public static function insecure(string $target, string $reason): self
    {
        return new self(ValidationStatus::Insecure, $target, $reason);
    }

    public static function bogus(string $target, string $reason): self
    {
        return new self(ValidationStatus::Bogus, $target, $reason);
    }

    public function isSecure(): bool
    {
        return $this->status === ValidationStatus::Secure;
    }

    public function isInsecure(): bool
    {
        return $this->status === ValidationStatus::Insecure;
    }

    public function isBogus(): bool
    {
        return $this->status === ValidationStatus::Bogus;
    }
}
