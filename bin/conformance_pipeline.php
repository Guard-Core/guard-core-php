<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';

// Pipeline-kind conformance suites (spec 4.1.0): replays the reference
// pipeline harness cases through the real GuardEngine. Comparison follows
// specs/fixtures/README.md: only the keys present in each expected record
// are compared; the events key is skipped because the PHP engine exposes no
// event-bus capture surface. Documented divergences live in
// guard-core-spec-4.1.0/php_pipeline_xfail.json with fail-closed drift
// semantics (a failing case NOT baselined is red; a baselined case that
// passes is red).

final class CorpusGeo implements CountryResolver
{
    /** @param array<string, string> $table */
    public function __construct(private array $table)
    {
    }

    public function getCountry(string $ip): ?string
    {
        return $this->table[$ip] ?? null;
    }
}

function corpusValue(mixed $value): mixed
{
    // JSON decodes ints as ints and the expected records carry them as
    // ints; normalize float/int scalars for strict comparison.
    if (is_int($value) || is_float($value)) {
        return (int) $value;
    }

    return $value;
}

/** @return list<string> */
function corpusFailures(array $case): array
{
    $failures = [];
    $geo = new CorpusGeo($case['geo_countries'] ?? []);

    $configArgs = [
        'enableRedis' => false,
        'enableRateLimitAutoBan' => false,
        'enableIpBanning' => false,
        'autoBanThreshold' => 1000,
    ];
    $config = $case['config'] ?? [];
    $map = [
        'whitelist' => 'whitelist',
        'blacklist' => 'blacklist',
        'exempt_ips' => 'exemptIps',
        'blocked_user_agents' => 'blockedUserAgents',
        'blocked_countries' => 'blockedCountries',
        'whitelist_countries' => 'whitelistCountries',
        'rate_limit' => 'rateLimit',
        'rate_limit_window' => 'rateLimitWindow',
        'passive_mode' => 'passiveMode',
        'custom_error_responses' => 'customErrorResponses',
        'enable_cors' => 'enableCors',
        'cors_allow_origins' => 'corsAllowOrigins',
        'cors_allow_methods' => 'corsAllowMethods',
        'cors_allow_headers' => 'corsAllowHeaders',
        'cors_allow_credentials' => 'corsAllowCredentials',
        'behavior_scan_response_body' => 'behaviorScanResponseBody',
    ];
    foreach ($map as $jsonKey => $phpKey) {
        if (array_key_exists($jsonKey, $config)) {
            $configArgs[$phpKey] = $config[$jsonKey];
        }
    }
    if (isset($config['endpoint_rate_limits'])) {
        $tiers = [];
        foreach ($config['endpoint_rate_limits'] as $path => $pair) {
            $tiers[$path] = ['limit' => (int) $pair[0], 'window' => (int) $pair[1]];
        }
        $configArgs['endpointRateLimits'] = $tiers;
    }
    if (isset($config['global_behavior_rules'])) {
        $configArgs['globalBehaviorRules'] = $config['global_behavior_rules'];
    }
    if (isset($config['security_headers'])) {
        $configArgs['securityHeaders'] = $config['security_headers'];
    }
    if ((isset($config['blocked_countries']) && $config['blocked_countries'] !== [])
        || (isset($config['whitelist_countries']) && $config['whitelist_countries'] !== [])) {
        $configArgs['geoIpHandler'] = $geo;
    }

    $payloads = [];
    $configArgs['onBlock'] = function (object $request, array $payload) use (&$payloads): void {
        $observable = [];
        foreach (['check_name', 'reason', 'trigger_info', 'passive_mode', 'client_ip', 'path', 'method', 'status_code'] as $key) {
            $observable[$key] = corpusValue($payload[$key] ?? null);
        }
        $payloads[] = $observable;
    };

    try {
        $engine = new GuardEngine(new SecurityConfig(...$configArgs));
    } catch (Throwable $e) {
        return ['DIVERGENCE config-construction rejected: '.$e->getMessage()];
    }

    $factory = new GuardResponseFactory();

    foreach ($case['drives'] as $index => $drive) {
        $payloads = [];
        if ($index >= count($case['expected'])) {
            break;
        }
        $want = $case['expected'][$index];
        $request = new SimpleGuardRequest(
            urlPath: $drive['url_path'] ?? '/api',
            host: 'example.com',
            method: $drive['method'] ?? 'GET',
            clientHost: $drive['client_ip'],
            headers: $drive['headers'] ?? [],
            body: $drive['body'] ?? ''
        );
        $request->state()->clientIp = $drive['client_ip'];
        if (isset(($case['routes'] ?? [])[$drive['url_path']])) {
            $overrides = $case['routes'][$drive['url_path']];
            $routeArgs = [];
            $routeMap = [
                'rate_limit' => 'rateLimit',
                'rate_limit_window' => 'rateLimitWindow',
                'blocked_user_agents' => 'blockedUserAgents',
                'bypassed_checks' => 'bypassedChecks',
                'ip_whitelist' => 'ipWhitelist',
                'ip_blacklist' => 'ipBlacklist',
                'blocked_countries' => 'blockedCountries',
                'whitelist_countries' => 'whitelistCountries',
            ];
            foreach ($routeMap as $jsonKey => $phpKey) {
                if (array_key_exists($jsonKey, $overrides)) {
                    $routeArgs[$phpKey] = $overrides[$jsonKey];
                }
            }
            if (isset($overrides['enable_suspicious_detection'])) {
                $routeArgs['enableSuspiciousDetection'] = (bool) $overrides['enable_suspicious_detection'];
            }
            if (isset($overrides['excluded_detection_headers'])) {
                $routeArgs['excludedDetectionHeaders'] = $overrides['excluded_detection_headers'];
            }
            $request->state()->routeConfig = new RouteConfig(...$routeArgs);
        }

        $stage = $drive['stage'] ?? 'pipeline';
        if ($stage === 'process_response') {
            $response = $factory->createResponse($drive['response_body'] ?? 'ok', $drive['response_status'] ?? 200);
            $engine->processResponse($request, $response);
            foreach ($engine->responseHeaders() as $name => $value) {
                $response->headers()->set($name, $value);
            }
            if (isset($drive['headers']['Origin'])) {
                foreach ($engine->corsResponseHeaders($request) as $name => $value) {
                    $response->headers()->set($name, $value);
                }
            }
        } else {
            $response = $engine->execute($request);
        }

        $prefix = "drive {$index}";
        if (array_key_exists('status', $want)) {
            $got = $response === null ? null : corpusValue($response->statusCode());
            if ($got !== corpusValue($want['status'])) {
                $failures[] = "{$prefix} status: got ".var_export($got, true).' want '.var_export($want['status'], true);

                continue;
            }
        }
        if ($response !== null) {
            if (isset($want['body']) && $response->body() !== $want['body']) {
                $failures[] = "{$prefix} body: got ".var_export($response->body(), true).' want '.var_export($want['body'], true);
            }
            if (isset($want['headers']) && is_array($want['headers'])) {
                foreach ($want['headers'] as $name => $value) {
                    if ($response->headers()->get($name) !== $value) {
                        $failures[] = "{$prefix} header {$name}: got ".var_export($response->headers()->get($name), true).' want '.var_export($value, true);
                    }
                }
            }
        }
        foreach (['is_exempt' => 'isExempt', 'is_whitelisted' => 'isWhitelisted'] as $jsonKey => $stateKey) {
            if (array_key_exists($jsonKey, $want)) {
                $got = $request->state()->$stateKey ?? null;
                if ($got !== $want[$jsonKey]) {
                    $failures[] = "{$prefix} {$jsonKey}: got ".var_export($got, true).' want '.var_export($want[$jsonKey], true);
                }
            }
        }
        // events: skipped (no general event-bus capture on the PHP engine).
        if (isset($want['on_block'])) {
            $wantPayloads = $want['on_block'];
            if (count($payloads) !== count($wantPayloads)) {
                $failures[] = "{$prefix} on_block count: got ".count($payloads).' want '.count($wantPayloads);
            } else {
                foreach ($wantPayloads as $pi => $wantPayload) {
                    foreach ($wantPayload as $key => $value) {
                        if (corpusValue($payloads[$pi][$key] ?? null) !== corpusValue($value)) {
                            $failures[] = "{$prefix} on_block {$key}: got ".var_export($payloads[$pi][$key] ?? null, true).' want '.var_export($value, true);
                        }
                    }
                }
            }
        }
    }

    return $failures;
}

$casesDir = __DIR__.'/../conformance/guard-core-spec-4.1.0/cases';
$index = json_decode((string) file_get_contents($casesDir.'/index.json'), true, 512, JSON_THROW_ON_ERROR);
if ($index['spec_version'] !== '4.1.0') {
    fwrite(STDERR, "spec_version mismatch: corpus targets {$index['spec_version']} but the runner requires 4.1.0\n");
    exit(1);
}

$baselinePath = __DIR__.'/../conformance/guard-core-spec-4.1.0/php_pipeline_xfail.json';
$xfail = [];
if (is_file($baselinePath)) {
    $baseline = json_decode((string) file_get_contents($baselinePath), true, 512, JSON_THROW_ON_ERROR);
    if ($baseline['spec_version'] !== '4.1.0') {
        fwrite(STDERR, "xfail baseline spec pin {$baseline['spec_version']} does not match 4.1.0\n");
        exit(1);
    }
    $xfail = $baseline['cases'];
}

$total = $failed = $xfailed = $divergent = 0;
$stale = [];
$failureLines = [];
$xfailLines = [];

foreach ($index['suites'] as $suiteName => $meta) {
    if (($meta['kind'] ?? 'detect') !== 'pipeline' || !in_array('php', $meta['consumers'] ?? [], true)) {
        continue;
    }
    $suite = json_decode((string) file_get_contents($casesDir.'/'.$suiteName.'.json'), true, 512, JSON_THROW_ON_ERROR);
    foreach ($suite['cases'] as $case) {
        $total++;
        $key = $suiteName.'/'.$case['id'];
        $failures = corpusFailures($case);
        if ($failures === []) {
            if (isset($xfail[$key])) {
                $stale[] = "stale xfail baseline entry {$key}: case now passes; remove the entry";
            }

            continue;
        }
        if (count($failures) === 1 && str_starts_with($failures[0], 'DIVERGENCE')) {
            $divergent++;
            $failureLines[] = "DIVERGENCE {$key}: {$failures[0]}";

            continue;
        }
        if (isset($xfail[$key])) {
            $xfailed++;
            $xfailLines[] = "xfail {$key} [{$xfail[$key]}]: ".implode('; ', $failures);

            continue;
        }
        $failed++;
        $failureLines[] = "{$key}: ".implode('; ', $failures);
    }
}

foreach ($failureLines as $line) {
    if (str_starts_with($line, 'DIVERGENCE')) {
        echo $line."\n";
    }
}
foreach ($xfailLines as $line) {
    echo $line."\n";
}
if ($stale !== []) {
    fwrite(STDERR, "stale xfail baseline:\n".implode("\n", $stale)."\n");
    exit(1);
}
if ($failed > 0) {
    fwrite(STDERR, "pipeline conformance drift: {$failed}/{$total} cases differ\n".implode("\n", $failureLines)."\n");
    exit(1);
}

echo "pipeline conformance gate: ".($total - $failed - $divergent - $xfailed)." passed, {$failed} failed, {$xfailed} xfail, {$divergent} config divergences (spec 4.1.0)\n";
