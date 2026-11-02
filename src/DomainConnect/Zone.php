<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

/**
 * The zone a template is applied to: the registrable apex plus an optional
 * host (sub-domain) inside it.
 */
readonly class Zone
{
    public function __construct(
        public string $apex,
        public string $host = '',
    ) {}

    public static function of(string $apex, string $host = ''): self
    {
        return new self(self::normalise($apex), self::normalise($host));
    }

    public function fqdn(): string
    {
        return $this->isApex() ? $this->apex : "{$this->host}.{$this->apex}";
    }

    public function isApex(): bool
    {
        return $this->host === '';
    }

    private static function normalise(string $name): string
    {
        return trim(strtolower($name), " \t\n\r\0\x0B.");
    }
}
