<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * Environment-driven SecurityConfig for the advanced example, with
 * production-oriented defaults. Keeping config in one place mirrors the
 * `app/security.py` module of the Python advanced example.
 */

/** @return list<string> */
function advanced_split_csv(string $raw): array
{
    $parts = explode(',', $raw);
    $out = [];
    foreach ($parts as $part) {
        $part = trim($part);
        if ($part !== '') {
            $out[] = $part;
        }
    }

    return $out;
}

function advanced_int_env(string $key, int $fallback): int
{
    $raw = trim((string) getenv($key));
    if ($raw === '' || !ctype_digit(ltrim($raw, '-'))) {
        return $fallback;
    }

    return (int) $raw;
}

/** Address headers the Python engine skips when scanning for ssrf patterns. */
function advanced_address_headers(): array
{
    return [
        'host', 'origin', 'via', 'x-forwarded-for', 'x-forwarded-host',
        'x-forwarded-proto', 'x-real-ip', 'x-client-ip', 'x-cluster-client-ip',
        'cf-connecting-ip', 'true-client-ip', 'fly-client-ip',
        'x-envoy-external-address',
    ];
}

function advanced_config(): SecurityConfig
{
    return new SecurityConfig(
        // Proxy trust: the app sits behind nginx (docker-compose.yml), so
        // only the compose network ranges are trusted for forwarded
        // headers, one hop deep. Lock these down to your real edge in
        // production.
        trustedProxies: advanced_split_csv(getenv('TRUSTED_PROXIES') ?: ''),
        trustedProxyDepth: advanced_int_env('TRUSTED_PROXY_DEPTH', 1),
        trustXForwardedProto: true,
        // Redis is required for shared state across replicas; compose wires
        // it in. RedisFailOpen=false keeps the default fail-secure posture.
        enableRedis: getenv('ENABLE_REDIS') !== '0',
        redisPrefix: getenv('REDIS_PREFIX') ?: 'guard_core:',
        // Rate limiting: global 30 req/60s per client, plus the /rate/burst
        // per-endpoint override. Per-route rate limits exist on RouteConfig
        // and are read by the pipeline in this port, but the GuardEngine
        // facade does not expose a route registry yet (see guard_mw.php),
        // so endpoint limits are expressed through endpointRateLimits.
        enableRateLimiting: true,
        rateLimit: advanced_int_env('RATE_LIMIT', 30),
        rateLimitWindow: advanced_int_env('RATE_LIMIT_WINDOW', 60),
        endpointRateLimits: [
            '/rate/burst' => ['limit' => 5, 'window' => 60],
        ],
        // IP banning: five violations earn a five minute ban, and hostile
        // categories can ban earlier through per-threat thresholds.
        enableIpBanning: true,
        autoBanThreshold: advanced_int_env('AUTO_BAN_THRESHOLD', 5),
        autoBanDuration: advanced_int_env('AUTO_BAN_DURATION', 300),
        threatBanConfig: [
            'sqli' => ['threshold' => 3, 'duration' => 1800],
            'xss' => ['threshold' => 5, 'duration' => 600],
        ],
        // Detection: every category, default detector tuning.
        enablePenetrationDetection: true,
        // See advanced_address_headers() above: without this, nginx's
        // forwarded headers get flagged as ssrf attempts.
        logSensitiveHeaders: advanced_address_headers(),
        // Edge filters.
        blockedUserAgents: ['badbot', 'evil-crawler', 'sqlmap'],
        blockCloudProviders: advanced_split_csv(getenv('BLOCK_CLOUD_PROVIDERS') ?: ''),
        // Consistent block body for the ban verdict (this port returns the
        // fixed "Too many requests" body for 429, so no 429 override here).
        customErrorResponses: [403 => 'Blocked by guard-core-php (advanced example)'],
        // Liveness/readiness probes never reach the pipeline.
        excludePaths: [
            '/docs', '/redoc', '/openapi.json', '/favicon.ico', '/static',
            '/health', '/ready',
        ],
        // Logging levels for request and suspicious-activity logs.
        logRequestLevel: getenv('LOG_REQUEST_LEVEL') ?: 'INFO',
        logSuspiciousLevel: getenv('LOG_SUSPICIOUS_LEVEL') ?: 'WARNING',
        // Agent wiring (comment-level): guard-core-php's only telemetry seam
        // is onBlock. The PHP agent (guard-agent-php,
        // https://github.com/Guard-Core/guard-agent-php) mirrors the Python
        // guard-agent's API: once its engine-event pipeline accepts these
        // payloads, replace the log line below with the agent call and set
        // GUARD_AGENT_* env vars here. enableAgent stays false because the
        // engine fails config validation on it (the feature is not ported
        // yet); do not turn it on.
        onBlock: static function (object $request, array $payload): void {
            file_put_contents('php://stderr', sprintf(
                "guard blocked %s %s from %s via %s: %s\n",
                $payload['method'],
                $payload['path'],
                $payload['client_ip'],
                $payload['check_name'],
                $payload['reason'],
            ));
        },
    );
}
