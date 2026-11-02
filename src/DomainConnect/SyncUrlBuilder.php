<?php

declare(strict_types=1);

namespace Cbox\Dns\DomainConnect;

use Cbox\Dns\DomainConnect\Contracts\Signer;
use Cbox\Dns\DomainConnect\Exceptions\InvalidApplyRequest;
use Cbox\Dns\DomainConnect\Exceptions\SyncFlowUnavailable;
use Cbox\Dns\DomainConnect\Support\HttpsUrl;

/**
 * Builds the signed Domain Connect synchronous-flow apply URL
 * (`{urlSyncUX}/v2/domainTemplates/providers/{providerId}/services/{serviceId}/apply?...&sig=...&key=...`).
 */
class SyncUrlBuilder
{
    /** Query parameters the flow itself uses; a template variable may not shadow them. */
    public const array RESERVED_PARAMETERS = ['domain', 'host', 'redirect_uri', 'state', 'groupid', 'sig', 'key'];

    public function __construct(
        private readonly Signer $signer,
        private readonly string $keyHost = '_dcpubkeyv1',
    ) {}

    public function build(ApplyRequest $request, ProviderSettings $settings): string
    {
        $template = $request->template;

        if ($settings->urlSyncUX === null) {
            throw SyncFlowUnavailable::because("provider [{$settings->providerId}] publishes no urlSyncUX");
        }

        if ($template->syncBlock) {
            throw SyncFlowUnavailable::because("template [{$template->providerId}/{$template->serviceId}] sets syncBlock");
        }

        $query = http_build_query($this->pairs($request), '', '&', PHP_QUERY_RFC3986);

        return HttpsUrl::base($settings->urlSyncUX)
            .'/v2/domainTemplates/providers/'.rawurlencode($template->providerId)
            .'/services/'.rawurlencode($template->serviceId)
            .'/apply?'.$query
            .'&sig='.rawurlencode($this->signer->sign($query))
            .'&key='.rawurlencode($this->keyHost);
    }

    /**
     * @return array<string, string>
     */
    private function pairs(ApplyRequest $request): array
    {
        $template = $request->template;
        $names = $template->variables();

        foreach ($names as $name) {
            if (in_array(strtolower($name), self::RESERVED_PARAMETERS, true)) {
                throw InvalidApplyRequest::because("template variable [{$name}] clashes with a built-in query parameter");
            }
        }

        foreach (array_keys($request->variables) as $key) {
            $name = (string) $key;

            if (! in_array($name, $names, true)) {
                throw InvalidApplyRequest::because("variable [{$name}] is not used by the template");
            }
        }

        foreach ($request->groupIds as $groupId) {
            if (! in_array($groupId, $template->groupIds(), true)) {
                throw InvalidApplyRequest::because("group [{$groupId}] is not defined by the template");
            }
        }

        $pairs = ['domain' => $request->zone->apex];

        if (! $request->zone->isApex()) {
            $pairs['host'] = $request->zone->host;
        }

        if ($request->redirectUri !== null) {
            $pairs['redirect_uri'] = $request->redirectUri;
        }

        if ($request->state !== null) {
            $pairs['state'] = $request->state;
        }

        foreach ($names as $name) {
            if (! array_key_exists($name, $request->variables)) {
                throw InvalidApplyRequest::because("variable [{$name}] has no value");
            }

            $pairs[$name] = $request->variables[$name];
        }

        if ($request->groupIds !== []) {
            $pairs['groupId'] = implode(',', array_unique($request->groupIds));
        }

        return $pairs;
    }
}
