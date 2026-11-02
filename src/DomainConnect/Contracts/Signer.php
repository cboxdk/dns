<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Contracts;

/**
 * Signs a Domain Connect synchronous-flow query string with the template
 * provider's private key (RS256: RSA PKCS#1 v1.5 over SHA-256).
 */
interface Signer
{
    /**
     * @return string the signature as standard base64, not URL-encoded
     */
    public function sign(string $query): string;
}
