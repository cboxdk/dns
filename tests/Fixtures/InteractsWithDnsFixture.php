<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Fixtures;

use Cbox\Dns\Testing\InteractsWithDns;

/**
 * A composition site for {@see InteractsWithDns} so PHPStan (which does not analyse
 * the Pest test files) still type-checks the trait against a concrete host class.
 */
class InteractsWithDnsFixture
{
    use InteractsWithDns;
}
