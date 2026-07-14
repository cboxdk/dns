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
final class DomainVerifier
{
    private const string CHALLENGE_PREFIX = '_cbox-challenge.';

    public function __construct(
        private readonly AuthoritativeResolver $resolver,
    ) {}

    /**
     * The fully-qualified host at which the verification TXT record must be published.
     */
    public function challengeHost(string $domain): string
    {
        return self::CHALLENGE_PREFIX.$this->normalize($domain);
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
            if (trim($record->value) === $token) {
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
