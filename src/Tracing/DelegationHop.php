<?php

declare(strict_types=1);

namespace Cbox\Dns\Tracing;

use Cbox\Dns\Enums\Rcode;

/**
 * One step of a delegation trace: the zone whose servers were asked, the specific
 * server that answered, and what it returned — either a referral down to a child
 * zone (with the child's nameservers and any glue) or the final authoritative
 * answer.
 */
readonly class DelegationHop
{
    /**
     * @param  string  $zone  the zone queried at this hop (`.` for the root)
     * @param  string  $serverName  the nameserver name asked (or the IP if unknown)
     * @param  string  $serverIp  the IP actually queried
     * @param  list<string>  $referralNameservers  the child zone's NS names, when this hop is a referral
     * @param  array<string, string>  $glue  referral nameserver name => its glue IP
     */
    public function __construct(
        public string $zone,
        public string $serverName,
        public string $serverIp,
        public bool $answered,
        public bool $authoritative,
        public Rcode $rcode,
        public ?string $childZone = null,
        public array $referralNameservers = [],
        public array $glue = [],
    ) {}

    public function isReferral(): bool
    {
        return $this->childZone !== null;
    }
}
