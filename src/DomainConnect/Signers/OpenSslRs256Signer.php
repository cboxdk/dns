<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Signers;

use Cbox\Dns\DomainConnect\Contracts\Signer;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * RS256 (RSA PKCS#1 v1.5 + SHA-256) via ext-openssl, the construction the
 * Domain Connect reference tooling uses for synchronous-flow signatures.
 */
class OpenSslRs256Signer implements Signer
{
    private readonly OpenSSLAsymmetricKey $key;

    public function __construct(string $privateKeyPem)
    {
        if (! function_exists('openssl_sign')) {
            throw new RuntimeException('Signing Domain Connect requests requires ext-openssl.');
        }

        $key = openssl_pkey_get_private($privateKeyPem);

        if ($key === false) {
            throw new RuntimeException('The Domain Connect signing private key could not be read.');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            throw new RuntimeException('The Domain Connect signing key must be an RSA private key.');
        }

        $this->key = $key;
    }

    public function sign(string $query): string
    {
        if (! openssl_sign($query, $signature, $this->key, OPENSSL_ALGO_SHA256) || ! is_string($signature)) {
            throw new RuntimeException('Signing the Domain Connect query failed.');
        }

        return base64_encode($signature);
    }
}
