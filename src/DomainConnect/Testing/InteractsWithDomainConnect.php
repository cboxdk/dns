<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect\Testing;

use Cbox\Dns\DomainConnect\DomainConnect;
use Cbox\Dns\Testing\InteractsWithDns;

/**
 * Domain Connect on top of {@see InteractsWithDns}: a shared fake transport and
 * signer, and a {@see DomainConnect} wired over them and the shared fake resolver.
 */
trait InteractsWithDomainConnect
{
    use InteractsWithDns;

    protected ?FakeTransport $fakeTransport = null;

    protected ?FakeSigner $fakeSigner = null;

    protected function fakeTransport(): FakeTransport
    {
        return $this->fakeTransport ??= new FakeTransport;
    }

    protected function fakeSigner(): FakeSigner
    {
        return $this->fakeSigner ??= new FakeSigner;
    }

    protected function domainConnect(string $keyHost = '_dcpubkeyv1'): DomainConnect
    {
        return $this->fakeDnsFacade()->domainConnect($this->fakeSigner(), $this->fakeTransport(), $keyHost);
    }
}
