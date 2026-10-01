<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\HttpResponse;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\PerformanceMonitor;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\GeoIp\IpInfoManager;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';
if (!function_exists('buildTestMmdb')) {
    require __DIR__ . '/../tests/MmdbFixture.php';
}

// events-kind conformance suite (spec 4.1.0 event_stream.json): drives the
// REAL PHP event seams (the spec 12 bus over the check pipeline, the
// monitor anomaly emitters, the geo event sink, the dynamic-rules manager)
// and captures full SecurityEvent envelopes with a capturing agent handler.
// Comparison follows index.json's events_envelopes block: only the keys
// present in each expected envelope are compared (a field the PHP envelope
// model cannot observe is recorded as null), volatile fields are dropped
// recursively (events_volatile_fields), floats round to 6 decimals.
// Corpus cases flagged xfail are advisory and skipped. Documented
// divergences live in guard-core-spec-4.1.0/php_events_xfail.json with
// fail-closed drift semantics: a failing case NOT baselined is red, a
// baselined case that now passes is red, and a case with no driver that is
// NOT baselined is red.

final class RuntimeError extends \RuntimeException
{
}

// The reference harness raises RuntimeError('corpus injected download
// failure'); IpInfoManager::describeDownloadError renders non-HTTP errors
// by class name only, matching the reference envelope.

final class EventsAgent
{
    /** @var list<SecurityEvent> */
    public array $received = [];

    /** @var array<string, mixed>|null */
    public ?array $rules = null;

    public function sendEvent(object $event): void
    {
        $this->received[] = $event;
    }

    public function getDynamicRules(): ?array
    {
        return $this->rules;
    }
}

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

final class ThrowingDownloadClient implements \RenzoFranceschini\GuardCore\Cloud\HttpClient
{
    public function get(string $url, array $options = []): HttpResponse
    {
        throw new RuntimeError('corpus injected download failure');
    }
}

final class RecordingBanSink implements \RenzoFranceschini\GuardCore\Ban\BanEventSink
{
    /** @var list<array{string, int, string}> */
    public array $bans = [];

    /** @var list<string> */
    public array $unbans = [];

    public function sendBanEvent(string $ip, int $duration, string $reason): void
    {
        $this->bans[] = [$ip, $duration, $reason];
    }

    public function sendUnbanEvent(string $ip): void
    {
        $this->unbans[] = $ip;
    }
}

final class EventsConformanceRunner
{
    private const VOLATILE_FIELDS = [
        'execution_time',
        'execution_time_ms',
        'idempotency_key',
        'response_time',
        'timestamp',
    ];

    private const FLOAT_PRECISION = 6;

    private string $casesDir;
    private string $baselinePath;
    private int $passed = 0;
    private int $xfailed = 0;
    private int $skipped = 0;
    private int $failed = 0;
    private int $total = 0;

    public function __construct(string $casesDir, string $baselinePath)
    {
        $this->casesDir = $casesDir;
        $this->baselinePath = $baselinePath;
    }

    /** @return array<string, string> the case id -> reason baseline */
    private function loadBaseline(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $baseline = json_decode((string) file_get_contents($this->baselinePath), true, 512, JSON_THROW_ON_ERROR);
        if (($baseline['spec_version'] ?? null) !== '4.1.0') {
            fwrite(STDERR, "xfail baseline spec pin {$baseline['spec_version']} does not match 4.1.0\n");
            exit(1);
        }

        return $baseline['cases'];
    }

    public function run(): int
    {
        $suite = json_decode(
            (string) file_get_contents($this->casesDir . '/event_stream.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $xfail = $this->loadBaseline();
        $stale = [];
        $failureLines = [];
        $xfailLines = [];

        foreach ($suite['cases'] as $case) {
            $id = $case['id'];
            if (($case['xfail'] ?? false) === true) {
                // Advisory corpus xfail: carries no expectations.
                $this->skipped++;
                echo "skip {$id} [advisory corpus xfail]: {$case['xfail_reason']}\n";

                continue;
            }
            $this->total++;
            $driver = $this->driverFor($case);
            if ($driver === null) {
                if (isset($xfail[$id])) {
                    $this->xfailed++;
                    $xfailLines[] = "xfail {$id} [{$xfail[$id]}]: no driver";

                    continue;
                }
                $this->failed++;
                $failureLines[] = "{$id}: no driver for the PHP engine and no baseline entry";

                continue;
            }
            try {
                $actual = array_map(self::envelope(...), $driver());
            } catch (Throwable $e) {
                $actual = null;
                $failureLines[] = "{$id}: driver threw " . $e::class . ": {$e->getMessage()} "
                    . '@ ' . $e->getFile() . ':' . $e->getLine();
            }
            if ($actual === null) {
                if (isset($xfail[$id])) {
                    $this->xfailed++;
                } else {
                    $this->failed++;
                }

                continue;
            }
            $diffs = $this->compare($case['expected'] ?? [], $actual);
            if ($diffs === []) {
                if (isset($xfail[$id])) {
                    $stale[] = $id;
                } else {
                    $this->passed++;
                    echo "PASS {$id}\n";
                }

                continue;
            }
            if (isset($xfail[$id])) {
                $this->xfailed++;
                $xfailLines[] = "xfail {$id} [{$xfail[$id]}]: " . implode('; ', array_slice($diffs, 0, 3));

                continue;
            }
            $this->failed++;
            foreach (array_slice($diffs, 0, 4) as $diff) {
                $failureLines[] = "{$id}: {$diff}";
            }
        }

        foreach ($xfailLines as $line) {
            echo $line . "\n";
        }
        if ($stale !== []) {
            fwrite(STDERR, "stale xfail baseline:\n" . implode("\n", $stale) . "\n");
            $this->failed += count($stale);
        }
        if ($this->failed > 0) {
            fwrite(STDERR, "events conformance drift: {$this->failed} cases differ\n"
                . implode("\n", $failureLines) . "\n");
            exit(1);
        }

        echo "events conformance gate: {$this->passed} passed, {$this->xfailed} xfail, "
            . "{$this->skipped} advisory skips (spec 4.1.0, {$this->total} driven cases)\n";

        return 0;
    }

    /**
     * The driver seam per case: pipeline cases run through GuardEngine,
     * handler-call cases through the matching PHP emitter. Null means the
     * PHP engine has no seam for the case at all (the case must then be
     * baselined with the missing-seam reason).
     *
     * @param array<string, mixed> $case
     * @return callable(): list<SecurityEvent>|null
     */
    private function driverFor(array $case): ?callable
    {
        return match ($case['id']) {
            'evt_penetration_attempt_blocked',
            'evt_penetration_attempt_passive',
            'evt_ip_blocked_global_blacklist',
            'evt_ip_banned_then_blocked',
            'evt_cloud_blocked_provider',
            'evt_https_enforced_redirect',
            'evt_decorator_violation_auth_required',
            'evt_content_filtered_max_size',
            'evt_emergency_mode_block',
            'evt_path_excluded_health',
            'evt_rate_limited_global',
            'evt_dynamic_rule_violation_endpoint',
            'evt_route_unresolved_strict',
            'evt_security_bypass_all',
            'evt_user_agent_blocked_global',
            'evt_suspicious_request_untrusted_proxy',
            'evt_custom_request_check_reject' => fn (): array => $this->drivePipeline($case),
            'evt_ip_ban_failed_escalation',
            'evt_ip_unbanned',
            'evt_behavioral_violation_usage_log',
            'evt_pattern_detected_xss',
            'evt_dynamic_rules_update_apply',
            'evt_emergency_mode_activated',
            'evt_access_denied_decorator',
            'evt_authentication_failed_decorator',
            'evt_country_blocked_geo',
            'evt_csp_violation_report',
            'evt_geo_lookup_failed_download',
            'evt_pattern_added_custom',
            'evt_pattern_removed_custom',
            'evt_rate_limit_script_reloaded',
            'evt_redis_connection_established',
            'evt_redis_error_connection_failed',
            'evt_detection_engine_callback_error',
            'evt_pattern_anomaly_timeout',
            'evt_pattern_anomaly_slow_execution',
            'evt_pattern_anomaly_statistical' => fn (): array => $this->driveCalls($case),
            default => null,
        };
    }

    /**
     * Pipeline drive: the case's sequential steps over one GuardEngine with
     * the bus wired to a capturing agent (the pipeline_harness drive kind).
     *
     * @param array<string, mixed> $case
     * @return list<SecurityEvent>
     */
    private function drivePipeline(array $case): array
    {
        $agent = new EventsAgent();
        $geo = new CorpusGeo($case['geo_countries'] ?? []);
        $configArgs = [
            'enableRedis' => false,
            'enableRateLimitAutoBan' => false,
            'enableIpBanning' => false,
            'autoBanThreshold' => 1000,
        ];
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
            'emergency_mode' => 'emergencyMode',
            'enforce_https' => 'enforceHttps',
            'exclude_paths' => 'excludePaths',
            'trusted_proxies' => 'trustedProxies',
            'route_resolution_strict' => 'routeResolutionStrict',
            'endpoint_rate_limits' => 'endpointRateLimits',
        ];
        $config = $case['config'] ?? [];
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
        if ((isset($config['blocked_countries']) && $config['blocked_countries'] !== [])
            || (isset($config['whitelist_countries']) && $config['whitelist_countries'] !== [])) {
            $configArgs['geoIpHandler'] = $geo;
        }
        if (($config['custom_request_check'] ?? null) === 'corpus_reject_all') {
            $factory = new GuardResponseFactory();
            $configArgs['customRequestCheck'] = static fn (object $request): object => $factory->createResponse('corpus rejected', 418);
        }

        $engine = new GuardEngine(
            new SecurityConfig(...$configArgs),
            null,
            null,
            null,
            $this->pinnedCloudManager($case)
        );
        $engine->eventBus()->setAgentHandler($agent);

        foreach ($case['drives'] as $drive) {
            if (isset($drive['call'])) {
                // The ban/unban handler-call drives run against the engine's
                // own ban manager: the sink seam is adapter-authored in PHP,
                // so the engine emits nothing for the ban itself.
                if (($drive['call'] === 'ban_ip' || $drive['call'] === 'unban_ip') && isset($drive['ip'])) {
                    $this->engineBanCall($engine, $drive);
                }

                continue;
            }
            $headers = $drive['headers'] ?? [];
            $body = (string) ($drive['body'] ?? '');
            if ($body !== '' && !isset($headers['Content-Length']) && !isset($headers['content-length'])) {
                // The adapter translation of a body-carrying request: the
                // engine's request_size_content check sizes the request from
                // the Content-Length header.
                $headers['Content-Length'] = (string) strlen($body);
            }
            $request = new SimpleGuardRequest(
                urlPath: $drive['url_path'] ?? '/api',
                host: 'example.com',
                method: $drive['method'] ?? 'GET',
                clientHost: $drive['client_ip'],
                headers: $headers,
                body: $body
            );
            if (!($drive['drop_cached_client_ip'] ?? false)) {
                $request->state()->clientIp = $drive['client_ip'];
            }
            $routeOverrides = ($case['routes'] ?? [])[$drive['url_path']] ?? null;
            if ($routeOverrides !== null) {
                $request->state()->routeConfig = $this->buildRouteConfig($routeOverrides);
            }
            $engine->execute($request);
        }

        return $agent->received;
    }

    /**
     * @param array<string, mixed> $drive
     */
    private function engineBanCall(GuardEngine $engine, array $drive): void
    {
        if ($drive['call'] === 'ban_ip') {
            $engine->banManager()->ban(
                (string) $drive['ip'],
                (int) ($drive['duration'] ?? 3600),
                (string) ($drive['reason'] ?? 'corpus_ban')
            );

            return;
        }
        $engine->banManager()->ban((string) $drive['ip'], 3600, 'corpus_ban');
        $engine->banManager()->unban((string) $drive['ip']);
    }

    /**
     * Handler-call drive: the direct emitter seams (the events_harness call
     * kind). Unsupported calls throw; the caller baselines them.
     *
     * @param array<string, mixed> $case
     * @return list<SecurityEvent>
     */
    private function driveCalls(array $case): array
    {
        $agent = new EventsAgent();
        foreach ($case['drives'] as $drive) {
            $op = $drive['call'] ?? null;
            match ($op) {
                'ban_ip' => $this->callBanIp($drive),
                'unban_ip' => $this->callUnbanIp($drive),
                'detect' => (new SusPatterns())->detect(
                    (string) $drive['content'],
                    (string) ($drive['ip'] ?? '203.0.113.7'),
                    (string) ($drive['context'] ?? 'body')
                ),
                'dynamic_rules' => $this->callDynamicRules($drive, $agent),
                'behavior_action' => $this->callBehaviorAction($drive),
                'monitor_anomaly' => $this->callMonitorAnomaly($drive, $agent),
                'monitor_callback_fault' => $this->callMonitorCallbackFault($drive, $agent),
                'geo_country_stub' => $this->callGeoCountryStub($drive, $agent),
                'geo_download_failure' => $this->callGeoDownloadFailure($agent),
                'ipban_fault', 'add_pattern', 'remove_pattern', 'decorator_event',
                'csp_report', 'headers_applied', 'redis_connect', 'redis_connect_error',
                'rate_limit_script_reload', 'bypass', 'path_excluded' => throw new RuntimeException(
                    "no PHP emitter seam for corpus call '{$op}'"
                ),
                default => throw new RuntimeException("unknown corpus call '{$op}'"),
            };
        }

        return $agent->received;
    }

    /** @param array<string, mixed> $drive */
    private function callBanIp(array $drive): void
    {
        $ban = new \RenzoFranceschini\GuardCore\Ban\IpBanManager([], null, new RecordingBanSink());
        $ban->ban((string) $drive['ip'], (int) ($drive['duration'] ?? 3600), (string) ($drive['reason'] ?? 'corpus_ban'));
    }

    /** @param array<string, mixed> $drive */
    private function callUnbanIp(array $drive): void
    {
        $ban = new \RenzoFranceschini\GuardCore\Ban\IpBanManager([], null, new RecordingBanSink());
        $ban->ban((string) $drive['ip'], 3600, 'corpus_ban');
        $ban->unban((string) $drive['ip']);
    }

    /** @param array<string, mixed> $drive */
    private function callDynamicRules(array $drive, EventsAgent $agent): void
    {
        $busAgent = new EventsAgent();
        $bus = new \RenzoFranceschini\GuardCore\Events\EventBus($busAgent, new SecurityConfig());
        // The reference harness's _rules_from_payload stamps the payload
        // with a fixed timestamp before parsing; mirror that here.
        $rules = $drive['rules'];
        $rules['timestamp'] = '2026-01-01T00:00:00+00:00';
        $manager = new DynamicRuleManager(
            config: new SecurityConfig(enableDynamicRules: true),
            agentHandler: new class($rules) {
                /** @param array<string, mixed> $rules */
                public function __construct(private array $rules)
                {
                }

                /** @return array<string, mixed> */
                public function getDynamicRules(): array
                {
                    return $this->rules;
                }
            },
            eventBus: $bus,
            logger: static function (string $level, string $message): void {
            },
            clock: static fn (): int => 1700000000
        );
        $manager->updateRules();
        foreach ($busAgent->received as $event) {
            $agent->received[] = $event;
        }
    }

    /** @param array<string, mixed> $drive */
    private function callBehaviorAction(array $drive): void
    {
        $rulePayload = $drive['rule'];
        $rule = new BehaviorRule(
            ruleType: (string) $rulePayload['rule_type'],
            threshold: (int) $rulePayload['threshold'],
            window: isset($rulePayload['window']) ? (int) $rulePayload['window'] : null
        );
        $tracker = new BehaviorTracker(new SecurityConfig(), null, null);
        $tracker->applyAction(
            $rule,
            (string) $drive['ip'],
            (string) ($drive['endpoint_id'] ?? 'corpus.endpoint'),
            (string) ($drive['details'] ?? 'Usage threshold exceeded: 1 calls in 60s')
        );
    }

    /** @param array<string, mixed> $drive */
    private function callMonitorAnomaly(array $drive, EventsAgent $agent): void
    {
        $monitor = new PerformanceMonitor(
            anomalyThreshold: (float) ($drive['anomaly_threshold'] ?? 3.0),
            slowPatternThreshold: (float) ($drive['slow_pattern_threshold'] ?? 0.1),
            minSamplesForAnomaly: (int) ($drive['min_samples_for_anomaly'] ?? 10)
        );
        foreach ($drive['samples'] ?? [] as $sample) {
            $monitor->recordMetric(
                (string) $sample['pattern'],
                (float) $sample['execution_time'],
                (int) ($sample['content_length'] ?? 128),
                (bool) ($sample['matched'] ?? false),
                (bool) ($sample['timeout'] ?? false),
                $agent
            );
        }
    }

    /** @param array<string, mixed> $drive */
    private function callMonitorCallbackFault(array $drive, EventsAgent $agent): void
    {
        $monitor = new PerformanceMonitor(minSamplesForAnomaly: 10);
        $monitor->registerAnomalyCallback(static function (array $anomaly): void {
            throw new RuntimeError('corpus injected callback failure');
        });
        $monitor->recordMetric(
            (string) $drive['pattern'],
            (float) ($drive['execution_time'] ?? 0.5),
            128,
            false,
            false,
            $agent
        );
    }

    /** @param array<string, mixed> $drive */
    private function callGeoCountryStub(array $drive, EventsAgent $agent): void
    {
        $mmdbPath = buildTestMmdb([(string) ($drive['network'] ?? '198.51.100.0/24') => (string) $drive['country']]);
        $sink = static function (object $event) use ($agent): void {
            $agent->received[] = $event;
        };
        $handler = new IpInfoManager(
            token: 'corpus-token',
            dbPath: $mmdbPath,
            eventSink: $sink
        );
        $handler->initialize();
        $handler->checkCountryAccess((string) $drive['ip'], (array) ($drive['blocked_countries'] ?? ['CN']));
    }

    private function callGeoDownloadFailure(EventsAgent $agent): void
    {
        $sink = static function (object $event) use ($agent): void {
            $agent->received[] = $event;
        };
        $handler = new IpInfoManager(
            token: 'corpus-token',
            dbPath: sys_get_temp_dir() . '/guard_core_corpus_geo_' . getmypid() . '/corpus.mmdb',
            httpClient: new ThrowingDownloadClient(),
            eventSink: $sink
        );
        try {
            $handler->initialize();
        } finally {
            @rmdir(dirname($handler->dbPath()));
        }
    }

    /**
     * The cloud_stub analogue: the reference harness pins the cloud
     * handler's lookup answers; here the same answers are pinned into the
     * engine's CloudManager range tables (private install(), reached by
     * reflection - the port's equivalent of the harness monkeypatch).
     *
     * @param array<string, mixed> $case
     */
    private function pinnedCloudManager(array $case): ?CloudManager
    {
        $stub = null;
        foreach ($case['drives'] ?? [] as $drive) {
            if (($drive['call'] ?? null) === 'cloud_stub') {
                $stub = $drive;
            }
        }
        if ($stub === null) {
            return null;
        }
        $manager = new CloudManager();
        $network = (string) ($stub['network'] ?? '203.0.113.0/24');
        $provider = (string) ($stub['provider'] ?? 'AWS');
        $install = new ReflectionMethod(CloudManager::class, 'install');
        $install->invoke($manager, $provider, [$network => true], [$network => (string) ($stub['region'] ?? '')]);

        return $manager;
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function buildRouteConfig(array $overrides): RouteConfig
    {
        $args = [];
        $map = [
            'rate_limit' => 'rateLimit',
            'rate_limit_window' => 'rateLimitWindow',
            'blocked_user_agents' => 'blockedUserAgents',
            'bypassed_checks' => 'bypassedChecks',
            'ip_whitelist' => 'ipWhitelist',
            'ip_blacklist' => 'ipBlacklist',
            'blocked_countries' => 'blockedCountries',
            'whitelist_countries' => 'whitelistCountries',
            'block_cloud_providers' => 'blockCloudProviders',
        ];
        foreach ($map as $jsonKey => $phpKey) {
            if (array_key_exists($jsonKey, $overrides)) {
                $args[$phpKey] = $overrides[$jsonKey];
            }
        }
        if (isset($overrides['auth_required'])) {
            $args['authRequired'] = $overrides['auth_required'];
        }
        if (isset($overrides['require_https'])) {
            $args['requireHttps'] = (bool) $overrides['require_https'];
        }
        if (isset($overrides['max_request_size'])) {
            $args['maxRequestSize'] = (int) $overrides['max_request_size'];
        }
        if (isset($overrides['enable_suspicious_detection'])) {
            $args['enableSuspiciousDetection'] = (bool) $overrides['enable_suspicious_detection'];
        }

        return new RouteConfig(...$args);
    }

    /**
     * The full PHP envelope of a captured SecurityEvent, keyed like the
     * corpus envelopes. Fields the PHP envelope model does not carry
     * (status_code, pattern_matched) are recorded as absent: the
     * comparison treats them as null.
     *
     * @return array<string, mixed>
     */
    private static function envelope(SecurityEvent $event): array
    {
        return self::normalize([
            'event_type' => $event->eventType,
            'ip_address' => $event->ipAddress,
            'country' => $event->country,
            'user_agent' => $event->userAgent,
            'action_taken' => $event->actionTaken,
            'reason' => $event->reason,
            'endpoint' => $event->endpoint,
            'method' => $event->method,
            'decorator_type' => $event->decoratorType,
            'rule_type' => $event->ruleType,
            'handler_name' => $event->handlerName,
            'metadata' => $event->metadata,
        ]);
    }

    /**
     * @param list<array<string, mixed>> $expected
     * @param list<array<string, mixed>> $actual
     * @return list<string>
     */
    private function compare(array $expected, array $actual): array
    {
        $diffs = [];
        if (count($expected) !== count($actual)) {
            $expectedTypes = implode(',', array_column($expected, 'event_type'));
            $actualTypes = implode(',', array_column($actual, 'event_type'));

            return ["envelope count: got " . count($actual) . " ({$actualTypes}) want " . count($expected) . " ({$expectedTypes})"];
        }
        foreach ($expected as $i => $want) {
            $got = $actual[$i] ?? null;
            foreach ($want as $key => $expectedValue) {
                $actualValue = self::normalize(($got ?? [])[$key] ?? null);
                if ($actualValue !== self::normalize($expectedValue)) {
                    $diffs[] = "envelope[{$i}].{$key}: got " . json_encode($actualValue)
                        . ' want ' . json_encode(self::normalize($expectedValue));
                }
            }
        }

        return $diffs;
    }

    /**
     * Drops volatile fields recursively, rounds floats to the corpus
     * precision, and collapses int/float scalars so JSON's 1 vs 1.0 never
     * decides a comparison.
     *
     * @return mixed
     */
    private static function normalize(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $item) {
                if (is_string($key) && in_array($key, self::VOLATILE_FIELDS, true)) {
                    continue;
                }
                $out[$key] = self::normalize($item);
            }
            ksort($out);

            return $out;
        }
        if (is_float($value)) {
            $rounded = round($value, self::FLOAT_PRECISION);

            return $rounded === round($rounded) ? (int) $rounded : $rounded;
        }
        if (is_int($value)) {
            return $value;
        }

        return $value;
    }
}

$root = dirname(__DIR__);
$runner = new EventsConformanceRunner(
    $root . '/conformance/guard-core-spec-4.1.0/cases',
    $root . '/conformance/guard-core-spec-4.1.0/php_events_xfail.json'
);
exit($runner->run());
