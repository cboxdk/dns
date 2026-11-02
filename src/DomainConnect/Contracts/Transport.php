<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Contracts;

use Cbox\Dns\DomainConnect\HttpResponse;

/**
 * The HTTP seam of the Domain Connect module. A transport failure is reported
 * as a response with status 0, never as an exception.
 */
interface Transport
{
    public function get(string $url): HttpResponse;
}
