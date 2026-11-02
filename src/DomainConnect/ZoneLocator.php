<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\Contracts\Resolver;
use Cbox\Dns\DomainConnect\Exceptions\ZoneNotFound;
use Cbox\Dns\Enums\RecordType;
use Cbox\Dns\Exceptions\DnsException;
use Cbox\Dns\Exceptions\InvalidName;
use Cbox\Dns\Support\Hostname;

/**
 * Finds the zone apex of a name by walking SOA records from the name upward.
 *
 * The first candidate that answers with a SOA record owned by exactly that
 * candidate is the apex; a SOA owned by a parent (as carried in a recursive
 * authority section) does not count. A single-label name (a TLD such as `com`)
 * is never an apex: a registrable zone has at least two labels.
 *
 * Names are converted to their ASCII (punycode) form before the walk, so the
 * {@see Zone} returned is always ASCII: `blåbær.dk` locates as `xn--blbr-roah.dk`.
 */
class ZoneLocator
{
    public function __construct(private readonly Resolver $resolver) {}

    /**
     * @throws ZoneNotFound when no SOA answers for the name or any parent below the TLD
     * @throws InvalidName when a non-ASCII name cannot be converted to punycode
     */
    public function locate(string $name): Zone
    {
        $normalised = strtolower(Hostname::toAscii(trim($name, " \t\n\r\0\x0B.")));
        $labels = $normalised === '' ? [] : explode('.', $normalised);

        for ($removed = 0; $removed < count($labels) - 1; $removed++) {
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
            if ($record->type === RecordType::SOA && self::ascii($record->name) === $candidate) {
                return true;
            }
        }

        return false;
    }

    private static function ascii(string $owner): ?string
    {
        try {
            return strtolower(Hostname::toAscii($owner));
        } catch (InvalidName) {
            return null;
        }
    }
}
