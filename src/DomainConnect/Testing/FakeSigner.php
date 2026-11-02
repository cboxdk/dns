<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Testing;

use Cbox\Dns\DomainConnect\Contracts\Signer;

/**
 * Returns a fixed signature (base64 of "fake-sig") and records every query
 * it was asked to sign.
 */
class FakeSigner implements Signer
{
    public const string SIGNATURE = 'ZmFrZS1zaWc=';

    /** @var list<string> */
    private array $signed = [];

    public function sign(string $query): string
    {
        $this->signed[] = $query;

        return self::SIGNATURE;
    }

    /**
     * @return list<string>
     */
    public function signed(): array
    {
        return $this->signed;
    }
}
