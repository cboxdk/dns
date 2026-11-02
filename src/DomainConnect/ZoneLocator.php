<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\DomainConnect\Exceptions\ZoneNotFound;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;

/**
 * Finds the zone apex of a name by walking SOA records from the name upward.
 *
 * The first candidate that answers with a SOA record owned by exactly that
 * candidate is the apex; a SOA owned by a parent (as carried in a recursive
 * authority section) does not count.
 */
class ZoneLocator
{
    public function __construct(private readonly Resolver $resolver) {}

    /**
     * @throws ZoneNotFound when no SOA answers for the name or any parent
     */
    public function locate(string $name): Zone
    {
        $normalised = trim(strtolower($name), " \t\n\r\0\x0B.");
        $labels = $normalised === '' ? [] : explode('.', $normalised);

        for ($removed = 0; $removed < count($labels); $removed++) {
            $candidate = implode('.', array_slice($labels, $removed));

            if ($this->hasSoa($candidate)) {
                return Zone::of($candidate, implode('.', array_slice($labels, 0, $removed)));
            }
        }

        throw ZoneNotFound::for($normalised);
    }

    private function hasSoa(string $candidate): bool
    {
        try {
            $response = $this->resolver->query($candidate, RecordType::SOA);
        } catch (DnsException) {
            return false;
        }

        foreach ($response->records as $record) {
            if ($record->type === RecordType::SOA && trim(strtolower($record->name), '.') === $candidate) {
                return true;
            }
        }

        return false;
    }
}
