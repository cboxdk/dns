<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

/**
 * What the DNS provider sent back on the redirect after a synchronous apply.
 */
readonly class ApplyOutcome
{
    public function __construct(
        public ?string $state = null,
        public ?string $error = null,
        public ?string $errorDescription = null,
    ) {}

    public function succeeded(): bool
    {
        return $this->error === null;
    }

    /**
     * Non-string values are treated as absent.
     *
     * @param  array<string, mixed>  $query
     */
    public static function fromQuery(array $query): self
    {
        $read = static fn (string $key): ?string => is_string($query[$key] ?? null) ? $query[$key] : null;

        return new self($read('state'), $read('error'), $read('error_description'));
    }
}
