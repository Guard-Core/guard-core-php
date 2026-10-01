<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Cloud\HttpResponse;
use RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\GeoIp\IpInfoManager;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;

require __DIR__ . '/../vendor/autoload.php';

// redis_interop-kind conformance suite (spec 4.1.0 redis_interop.json): one
// operation per key family against the real PHP handlers pointed at the live
// Redis under the case's prefix, flushed before and after every case.
// Comparison follows index.json's redis_interop block: byte equality for
// keys, static string values and TTL semantics; engine-generated zset
// members and ban expiry floats are pinned by SHAPE (regex); zset scores
// compare as floats at 6-decimal precision; json values compare
// parsed-then-canonicalized with volatile fields dropped. Documented
// divergences live in guard-core-spec-4.1.0/php_redis_interop_xfail.json
// with fail-closed drift semantics (a failing case NOT baselined is red; a
// baselined case that passes is red).

final class RioStubDatabaseClient implements \RenzoFranceschini\GuardCore\Cloud\HttpClient
{
    public function get(string $url, array $options = []): HttpResponse
    {
        // The reference fixture's raw download bytes (redis_interop_cases.py
        // FAKE_MMDB_BYTES).
        return new HttpResponse(200, "corpus-mmdb-fixture:\xE9\xFF\x00\x80:end");
    }
}

final class RedisInteropRunner
{
    private const FLOAT_PRECISION = 6;

    private RedisHandler $redis;
    private string $casesDir;
    private string $baselinePath;
    private int $passed = 0;
    private int $xfailed = 0;
    private int $failed = 0;
    private int $total = 0;

    /** Deterministic epoch for every engine-driven timestamp (2026 era). */
    private const NOW = 1767225600.5;

    public function __construct(string $casesDir, string $baselinePath, string $redisHost)
    {
        $connection = new \RenzoFranceschini\GuardCore\Redis\RespConnection(
            $redisHost,
            (int) (getenv('REDIS_PORT') ?: 6379)
        );
        $connection->ping();
        $this->redis = new RedisHandler(true, 'guard_core:', connection: $connection);
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
            (string) file_get_contents($this->casesDir . '/redis_interop.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $xfail = $this->loadBaseline();
        $stale = [];
        $failureLines = [];
        $xfailLines = [];

        foreach ($suite['cases'] as $case) {
            $this->total++;
            $id = $case['id'];
            $this->flushPrefix((string) $case['prefix']);
            try {
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
                $driver($case);
                $diffs = $this->verify($case['expected']);
            } catch (Throwable $e) {
                $diffs = ['driver threw ' . $e::class . ': ' . $e->getMessage()
                    . ' @ ' . $e->getFile() . ':' . $e->getLine()];
            }
            $this->flushPrefix((string) $case['prefix']);
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
            fwrite(STDERR, "redis interop drift: {$this->failed} cases differ\n" . implode("\n", $failureLines) . "\n");
            exit(1);
        }

        echo "redis interop conformance gate: {$this->passed} passed, {$this->xfailed} xfail "
            . "(spec 4.1.0, {$this->total} cases)\n";

        return 0;
    }

    private function flushPrefix(string $prefix): void
    {
        $keys = $this->redis->connection()->keys($prefix . '*');
        if ($keys !== []) {
            $this->redis->connection()->del(...$keys);
        }
    }

    /**
     * The driver seam per corpus operation. Null means the PHP engine has
     * no seam for the operation (the case must then be baselined with the
     * missing-seam reason).
     *
     * @param array<string, mixed> $case
     * @return callable(array<string, mixed>): void|null
     */
    private function driverFor(array $case): ?callable
    {
        return match ($case['operation']['op'] ?? '') {
            'rate_limit' => function (array $case): void {
                $args = $case['operation']['args'];
                $handler = new RateLimitHandler(
                    new RateLimitConfig(
                        enableRateLimiting: true,
                        rateLimit: (int) $args['rate_limit'],
                        rateLimitWindow: (int) $args['rate_limit_window'],
                        enableRedis: true
                    ),
                    clock: static fn (): float => self::NOW
                );
                $handler->initializeRedis($this->prefixedHandler((string) $case['prefix']));
                $allowed = $handler->checkRateLimitByIp(
                    (string) $args['client_ip'],
                    (string) ($args['endpoint_path'] ?? '')
                );
                if (!$allowed) {
                    throw new RuntimeException('the first corpus rate limit hit must be allowed');
                }
            },
            'ban_ip' => function (array $case): void {
                $args = $case['operation']['args'];
                $ban = new IpBanManager();
                $ban->initializeRedis($this->prefixedHandler((string) $case['prefix']));
                $ban->ban((string) $args['ip'], (int) $args['duration'], (string) ($args['reason'] ?? 'rio_ban'));
            },
            'behavior_usage' => function (array $case): void {
                $args = $case['operation']['args'];
                $tracker = new BehaviorTracker(new SecurityConfig(), $this->prefixedHandler((string) $case['prefix']), null);
                $exceeded = $tracker->trackEndpointUsage(
                    (string) $args['endpoint_id'],
                    (string) $args['client_ip'],
                    $this->buildRule($args['rule']),
                    self::NOW
                );
                if ($exceeded) {
                    throw new RuntimeException('the first corpus usage hit must not exceed the threshold');
                }
            },
            'behavior_return' => function (array $case): void {
                $args = $case['operation']['args'];
                $tracker = new BehaviorTracker(new SecurityConfig(), $this->prefixedHandler((string) $case['prefix']), null);
                $response = (new GuardResponseFactory())->createResponse('corpus', (int) $args['response_status']);
                $exceeded = $tracker->trackReturnPattern(
                    (string) $args['endpoint_id'],
                    (string) $args['client_ip'],
                    $response,
                    $this->buildRule($args['rule']),
                    self::NOW
                );
                if ($exceeded) {
                    throw new RuntimeException('the first corpus return hit must not exceed the threshold');
                }
            },
            'ipinfo_database' => function (array $case): void {
                $args = $case['operation']['args'];
                $scratch = sys_get_temp_dir() . '/guard_core_corpus_rio_' . getmypid();
                @mkdir($scratch, 0777, true);
                $handler = new IpInfoManager(
                    token: 'corpus-token',
                    dbPath: $scratch . '/corpus.mmdb',
                    maxAge: (int) $args['max_age'],
                    httpClient: new RioStubDatabaseClient(),
                    redisHandler: $this->prefixedHandler((string) $case['prefix'])
                );
                try {
                    $handler->initialize();
                } finally {
                    @unlink($scratch . '/corpus.mmdb');
                    @rmdir($scratch);
                }
            },
            'cloud_ip_store' => function (array $case): void {
                $args = $case['operation']['args'];
                $store = new RedisCloudIpStore($this->prefixedHandler((string) $case['prefix']));
                $store->set(
                    (string) $args['provider'],
                    array_map(strval(...), (array) $args['ranges']),
                    isset($args['ttl']) ? (int) $args['ttl'] : null
                );
            },
            'dynamic_rules' => function (array $case): void {
                $args = $case['operation']['args'];
                $manager = new DynamicRuleManager(
                    config: new SecurityConfig(enableDynamicRules: true),
                    agentHandler: new class($args['rules']) {
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
                    redisHandler: $this->prefixedHandler((string) $case['prefix']),
                    logger: static function (string $level, string $message): void {
                    },
                    clock: static fn (): int => (int) self::NOW
                );
                $manager->updateRules();
            },
            // The PHP port's fetcher-bound cloud refresh path and the
            // security-headers / custom-pattern registries have no seam for
            // these operations; each is baselined with its source reason.
            'cloud_ranges', 'security_headers', 'add_pattern' => null,
            default => null,
        };
    }

    private function prefixedHandler(string $prefix): RedisHandler
    {
        return new RedisHandler(true, $prefix, connection: $this->redis->connection());
    }

    /**
     * @param array<string, mixed> $rulePayload
     */
    private function buildRule(array $rulePayload): BehaviorRule
    {
        return new BehaviorRule(
            ruleType: (string) $rulePayload['rule_type'],
            threshold: (int) $rulePayload['threshold'],
            window: isset($rulePayload['window']) ? (int) $rulePayload['window'] : null,
            pattern: isset($rulePayload['pattern']) ? (string) $rulePayload['pattern'] : null
        );
    }

    /**
     * @param list<array<string, mixed>> $expected
     * @return list<string>
     */
    private function verify(array $expected): array
    {
        $diffs = [];
        $connection = $this->redis->connection();
        foreach ($expected as $i => $want) {
            $key = (string) $want['key'];
            $type = (string) $want['type'];
            $exists = $connection->exists($key);
            if (!$exists) {
                $diffs[] = "record[{$i}]: key {$key} missing";

                continue;
            }
            $redisType = $connection->command('TYPE', $key);
            $wantType = match ($type) {
                'zset' => 'zset',
                'string', 'json' => 'string',
            };
            if ($redisType !== $wantType) {
                $diffs[] = "record[{$i}]: type got {$redisType} want {$wantType}";

                continue;
            }
            $ttlDiffs = $this->verifyTtl($connection, $key, $i, $want['ttl'] ?? []);
            foreach ($ttlDiffs as $diff) {
                $diffs[] = $diff;
            }
            if ($type === 'zset') {
                $rows = $connection->command('ZRANGE', $key, '0', '-1', 'WITHSCORES');
                $card = count($rows) / 2;
                if (isset($want['card']) && (int) $want['card'] !== $card) {
                    $diffs[] = "record[{$i}]: card got {$card} want {$want['card']}";
                }
                for ($m = 0; $m < (int) $card; $m++) {
                    $member = (string) $rows[$m * 2];
                    $score = (float) $rows[$m * 2 + 1];
                    if (isset($want['member_shape']) && preg_match('~' . $want['member_shape'] . '~', $member) !== 1) {
                        $diffs[] = "record[{$i}] member[{$m}]: shape mismatch on " . $member;
                    }
                    if (isset($want['score_shape']) && preg_match('~' . $want['score_shape'] . '~', (string) $rows[$m * 2 + 1]) !== 1) {
                        $diffs[] = "record[{$i}] score[{$m}]: shape mismatch on " . $rows[$m * 2 + 1];
                    }
                    if (!empty($want['score_equals_member'])
                        && abs($score - (float) $member) > 10 ** -self::FLOAT_PRECISION) {
                        $diffs[] = "record[{$i}] member[{$m}]: score {$score} != member {$member}";
                    }
                }
            } else {
                $value = (string) $connection->get($key);
                if (isset($want['value_shape']) && preg_match('~' . $want['value_shape'] . '~', $value) !== 1) {
                    $diffs[] = "record[{$i}]: value shape mismatch on " . substr($value, 0, 60);
                }
                if (array_key_exists('value', $want)) {
                    if ($type === 'json') {
                        $got = self::canonicalJson($value);
                        $wantValue = self::canonicalJson((string) $want['value']);
                        if ($got !== $wantValue) {
                            $diffs[] = "record[{$i}]: json value got " . json_encode($got)
                                . ' want ' . json_encode($wantValue);
                        }
                    } elseif ($value !== (string) $want['value']) {
                        $diffs[] = "record[{$i}]: value got " . substr($value, 0, 60)
                            . ' want ' . substr((string) $want['value'], 0, 60);
                    }
                }
            }
        }

        return $diffs;
    }

    /**
     * @return list<string>
     */
    private function verifyTtl(object $connection, string $key, int $i, array $ttl): array
    {
        $wantSet = (bool) ($ttl['set'] ?? false);
        $pttl = $connection->pttl($key);
        if (!$wantSet) {
            if ($pttl !== -1) {
                return ["record[{$i}]: ttl got " . var_export($pttl, true) . ' want no expiry'];
            }

            return [];
        }
        $seconds = (int) $ttl['seconds'];
        if ($pttl <= 0) {
            return ["record[{$i}]: ttl got " . var_export($pttl, true) . ' want an expiry of ' . $seconds . 's'];
        }
        $remainingSeconds = $pttl / 1000;
        // The configured value is never the remaining time; the op ran less
        // than 5 seconds ago, so the remainder must sit just under it.
        if ($remainingSeconds > $seconds || $remainingSeconds < $seconds - 5) {
            return ["record[{$i}]: ttl remaining {$remainingSeconds}s outside the configured {$seconds}s"];
        }

        return [];
    }

    /**
     * Parsed-then-canonicalized JSON: recursive key sort (JSON objects are
     * order-insensitive), floats rounded to the corpus precision. Payload
     * fields are all kept: the corpus's expected snapshots carry their
     * payload timestamps, so nothing is dropped here.
     *
     * @return mixed
     */
    private static function canonicalJson(string $payload): mixed
    {
        $decoded = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);

        return self::normalize($decoded);
    }

    private static function normalize(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $item) {
                $out[$key] = self::normalize($item);
            }
            ksort($out);

            return $out;
        }
        if (is_float($value)) {
            $rounded = round($value, self::FLOAT_PRECISION);

            return $rounded === round($rounded) ? (int) $rounded : $rounded;
        }

        return $value;
    }
}

$redisHost = getenv('REDIS_HOST') ?: '127.0.0.1';
$root = dirname(__DIR__);
$runner = new RedisInteropRunner(
    $root . '/conformance/guard-core-spec-4.1.0/cases',
    $root . '/conformance/guard-core-spec-4.1.0/php_redis_interop_xfail.json',
    $redisHost
);
exit($runner->run());
