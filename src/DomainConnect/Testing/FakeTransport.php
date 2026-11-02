<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Testing;

use Cbox\Dns\DomainConnect\Contracts\Transport;
use Cbox\Dns\DomainConnect\HttpResponse;
use LogicException;
use PHPUnit\Framework\Assert;

class FakeTransport implements Transport
{
    /** @var array<string, HttpResponse> */
    private array $stubs = [];

    /** @var list<string> */
    private array $requests = [];

    /** @var array<string, string|null> */
    private array $pinned = [];

    private bool $strict = false;

    /**
     * @param  string|array<mixed>  $body  an array is JSON-encoded
     */
    public function stub(string $url, int $status, string|array $body): self
    {
        $this->stubs[$url] = new HttpResponse(
            $status,
            is_array($body) ? json_encode($body, JSON_THROW_ON_ERROR) : $body,
        );

        return $this;
    }

    public function strict(bool $strict = true): self
    {
        $this->strict = $strict;

        return $this;
    }

    public function get(string $url, ?string $resolvedIp = null): HttpResponse
    {
        $this->requests[] = $url;
        $this->pinned[$url] = $resolvedIp;

        if (isset($this->stubs[$url])) {
            return $this->stubs[$url];
        }

        if ($this->strict) {
            throw new LogicException("No stub registered for [{$url}].");
        }

        return new HttpResponse(0, '');
    }

    /**
     * @return list<string>
     */
    public function requests(): array
    {
        return $this->requests;
    }

    /**
     * The address each requested URL was pinned to (null: not pinned); the
     * latest request wins for a repeated URL.
     *
     * @return array<string, string|null>
     */
    public function pinned(): array
    {
        return $this->pinned;
    }

    public function assertRequested(string $url): void
    {
        Assert::assertContains($url, $this->requests, "Expected a request to [{$url}].");
    }
}
