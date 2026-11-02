<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use JsonException;

readonly class HttpResponse
{
    public function __construct(
        public int $status,
        public string $body,
    ) {}

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status <= 299;
    }

    /**
     * The body decoded as a JSON object, or null when it is not one.
     *
     * @return array<string, mixed>|null
     */
    public function json(): ?array
    {
        try {
            $decoded = json_decode($this->body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        if (! is_array($decoded)) {
            return null;
        }

        $data = [];

        foreach ($decoded as $key => $value) {
            if (! is_string($key)) {
                return null;
            }

            $data[$key] = $value;
        }

        return $data;
    }
}
