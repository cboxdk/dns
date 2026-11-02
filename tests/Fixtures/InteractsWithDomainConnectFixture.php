<?php

declare(strict_types=1);

namespace Cbox\Dns\Tests\Fixtures;

use Cbox\Dns\DomainConnect\Testing\InteractsWithDomainConnect;

/**
 * A composition site for {@see InteractsWithDomainConnect} so PHPStan (which does
 * not analyse the Pest test files) type-checks the trait against a concrete class.
 */
class InteractsWithDomainConnectFixture
{
    use InteractsWithDomainConnect;
}
