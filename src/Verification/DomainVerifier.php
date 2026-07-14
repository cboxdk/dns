<?php

declare(strict_types=1);

namespace Cbox\Dns\Verification;

use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Resolvers\AuthoritativeResolver;

/**
 * Proves domain ownership by reading a TXT challenge record straight from the
 * domain's authoritative nameservers — never a recursive resolver's cache, which
 * an attacker on a shared resolver could poison or which could simply be stale.
 *
 * Deny-by-default: any resolution failure, or a challenge record that is absent
 * or does not match the expected token exactly, yields `false`.
 */
class DomainVerifier
{
    private const string DEFAULT_CHALLENGE_PREFIX = '_cbox-challenge';

    private readonly string $challengePrefix;

    /**
     * @param  string  $challengePrefix  the label prefixed to the domain for the
     *                                   challenge host — configurable so a consumer
     *                                   is not forced to publish a cbox-branded TXT
     *                                   record (e.g. `_acme-challenge`, `_myapp`).
     */
    public function __construct(
        private readonly AuthoritativeResolver $resolver,
        string $challengePrefix = self::DEFAULT_CHALLENGE_PREFIX,
    ) {
        $this->challengePrefix = rtrim($challengePrefix, '.');
    }

    /**
     * The fully-qualified host at which the verification TXT record must be published.
     */
    public function challengeHost(string $domain): string
    {
        return $this->challengePrefix.'.'.$this->normalize($domain);
    }

    /**
     * Whether the domain publishes a challenge TXT record matching `$token`
     * (exact, trimmed) at its authoritative nameservers.
     */
    public function verify(string $domain, string $token): bool
    {
        $domain = $this->normalize($domain);
        $token = trim($token);

        if ($domain === '' || $token === '') {
            return false;
        }

        try {
            $response = $this->resolver->query($this->challengeHost($domain), RecordType::TXT, $domain);
        } catch (DnsException) {
            return false;
        }

        foreach ($response->records as $record) {
            if (hash_equals($token, trim($record->value))) {
                return true;
            }
        }

        return false;
    }

    private function normalize(string $domain): string
    {
        return strtolower(trim(trim($domain), ".@\t\n\r "));
    }
}
