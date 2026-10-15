<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\BlockEvents;
use RenzoFranceschini\GuardCore\Request\GuardRequest;

final class LogActivity
{
    private function __construct()
    {
    }

    /**
     * log_activity semantics (spec 03, _utils/request_logging.py): dispatch
     * the block hook for suspicious logs (stash on short-circuit paths in
     * non-passive mode, immediate fire in passive mode), then emit the log
     * line unless the level is null or the check is muted.
     */
    public static function log(
        GuardRequest $request,
        RequestLogger $logger,
        SecurityConfig $config,
        string $logType = 'request',
        ?string $level = 'WARNING',
        string $reason = '',
        bool $passiveMode = false,
        string $triggerInfo = '',
        ?string $checkName = null
    ): void {
        if ($logType === 'suspicious') {
            if (!$passiveMode) {
                $request->state()->guardBlockStash = ['reason' => $reason, 'trigger_info' => $triggerInfo];
            } else {
                BlockEvents::fire(
                    $config->onBlock,
                    $request,
                    BlockEvents::buildPayload($request, $checkName ?? '', $reason, $triggerInfo, true, null)
                );
            }
        }
        if ($level === null) {
            return;
        }
        if ($checkName !== null && isset($config->mutedCheckLogs[strtolower($checkName)])) {
            return;
        }
        $context = self::extractRequestContext($request, $config);
        $message = self::buildMessage($context, $logType, $reason, $passiveMode, $triggerInfo);
        $logger->log(strtolower($level), $message, [
            'check' => $checkName ?? '',
            'path' => $request->urlPath(),
            'method' => $request->method(),
        ]);
    }

    /** @param array<string, string> $context */
    private static function headersSegment(array $headers): string
    {
        $parts = [];
        foreach ($headers as $name => $value) {
            $parts[] = $name . '=' . $value;
        }

        return implode(', ', $parts);
    }

    private static function buildMessage(
        array $context,
        string $logType,
        string $reason,
        bool $passiveMode,
        string $triggerInfo
    ): string {
        if ($logType === 'request') {
            $details = 'Request from ' . $context['client_ip'] . ': ' . $context['method'] . ' ' . $context['url'];
            $reasonMessage = 'Headers: ' . self::headersSegment($context['headers']);
        } elseif ($logType === 'suspicious') {
            // Without a trigger (for example a passive rate-limit hit) the line
            // is not a penetration attempt: it names itself suspicious activity
            // and keeps the reason (guard-core #165).
            $lead = $passiveMode && $triggerInfo !== ''
                ? '[PASSIVE MODE] Penetration attempt detected from'
                : ($passiveMode ? '[PASSIVE MODE] Suspicious activity detected from' : 'Suspicious activity detected from');
            $details = $lead . ' ' . $context['client_ip'] . ': ' . $context['method'] . ' ' . $context['url'];
            if ($passiveMode && $triggerInfo !== '') {
                $reasonMessage = 'Trigger: ' . $triggerInfo . ' - Headers: ' . self::headersSegment($context['headers']);
            } else {
                $reasonMessage = 'Reason: ' . $reason . ' - Headers: ' . self::headersSegment($context['headers']);
            }
        } else {
            $details = ucfirst($logType) . ' from ' . $context['client_ip'] . ': ' . $context['method'] . ' ' . $context['url'];
            $reasonMessage = 'Details: ' . $reason . ' - Headers: ' . self::headersSegment($context['headers']);
        }

        return LogSanitizer::sanitize($details . ' - ' . $reasonMessage);
    }

    /** @return array<string, string> */
    private static function extractRequestContext(GuardRequest $request, SecurityConfig $config): array
    {
        $extraHeaders = array_keys($config->logSensitiveHeaders);
        $extraParams = array_keys($config->logSensitiveParams);
        $extraBodyFields = array_keys($config->logSensitiveBodyFields);
        $clientIp = $request->state()->clientIp ?? $request->clientHost() ?? 'unknown';

        return [
            'client_ip' => $clientIp,
            'method' => $request->method(),
            'url' => LogRedactor::redactUrlForDisplay($request->urlFull(), $extraParams, $extraBodyFields, $extraHeaders),
            'headers' => LogRedactor::redactHeaders($request->headers()->all(), $extraHeaders, $extraBodyFields, $extraParams),
        ];
    }
}
