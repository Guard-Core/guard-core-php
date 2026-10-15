<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;

final class BlockEvents
{
    public const ON_BLOCK_EXCLUDED_CHECK_NAMES = ['custom_request', 'custom_validators', 'https_enforcement'];

    /**
     * Payload keys per spec 02 (on_block) / _utils/block_events.py.
     *
     * @return array<string, mixed>
     */
    public static function buildPayload(
        object $request,
        string $checkName,
        string $reason,
        string $triggerInfo,
        bool $passiveMode,
        ?int $statusCode
    ): array {
        $host = $request->clientHost();
        $clientIp = $request->state()->clientIp ?? ($host !== null && $host !== '' ? CanonicalIp::canonicalize($host) : $host);

        return [
            'check_name' => $checkName,
            'reason' => $reason,
            'trigger_info' => $triggerInfo,
            'passive_mode' => $passiveMode,
            'client_ip' => $clientIp,
            'path' => $request->urlPath(),
            'method' => $request->method(),
            'status_code' => $statusCode,
        ];
    }

    /** @param array<string, mixed> $payload */
    public static function fire(?\Closure $hook, object $request, array $payload): void
    {
        if ($hook === null || in_array($payload['check_name'], self::ON_BLOCK_EXCLUDED_CHECK_NAMES, true)) {
            return;
        }
        try {
            $hook($request, $payload);
        } catch (\Throwable) {
        }
    }
}
