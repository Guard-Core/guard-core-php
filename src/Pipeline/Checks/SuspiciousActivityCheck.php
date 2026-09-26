<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Behavior\SuspiciousCountStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
use RenzoFranceschini\GuardCore\Detection\HeaderExclusions;
use RenzoFranceschini\GuardCore\Detection\JsonWalk;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class SuspiciousActivityCheck extends SecurityCheck
{
    private const MAX_TRACKED_IPS = 10000;

    /** @var array<string, int> */
    private array $suspiciousCounts = [];

    /**
     * The shared per-category store (the engine owns it so the behavioral
     * processor's correlate_with_detection reads the same counts, mirroring
     * the reference reading middleware.suspicious_request_counts).
     */
    private readonly SuspiciousCountStore $suspiciousCountStore;

    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly SusPatterns $susPatterns,
        private readonly ?IpBanManager $ipBanManager,
        private readonly RouteResolver $routeResolver,
        ?SuspiciousCountStore $suspiciousCountStore = null
    ) {
        parent::__construct($config, $responseFactory);
        $this->suspiciousCountStore = $suspiciousCountStore ?? new SuspiciousCountStore();
    }

    public function checkName(): string
    {
        return 'suspicious_activity';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        // The reference route_config_applies gate: the check also runs when
        // any registered route enables per-route detection (the RouteConfig
        // default), even with the global flag off.
        if ($config->enablePenetrationDetection) {
            return true;
        }
        if ($routeConfigs === null) {
            return false;
        }
        foreach ($routeConfigs as $routeConfig) {
            if ($routeConfig->enableSuspiciousDetection) {
                return true;
            }
        }

        return false;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null || $request->state()->isWhitelisted) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;
        if ($this->routeResolver->shouldBypassCheck('penetration', $routeConfig)) {
            return null;
        }

        // The per-route enable_suspicious_detection decorator wins over the
        // global flag for routed requests (_get_effective_penetration_setting,
        // guard_core/core/checks/helpers.py): route true enables detection on
        // this route even when the global flag is off, route false disables
        // it even when the global flag is on (the reference's
        // disabled_by_decorator miss; the decorator-violation event rides
        // the documented event deferral).
        $penetrationEnabled = $routeConfig !== null
            ? $routeConfig->enableSuspiciousDetection
            : $this->config->enablePenetrationDetection;
        if (!$penetrationEnabled) {
            return null;
        }
        $enabledCategories = $this->resolveEnabledCategories($routeConfig);

        $categories = [];
        foreach ($this->scanValues($request) as [$content, $context, $forcedCategory, $skipCategories]) {
            if ($forcedCategory !== null) {
                // JSON mongo-operator keys report straight from the walk
                // (body_json_scan._mongo_operator_key_hit) without a pattern
                // scan.
                if (isset($enabledCategories[$forcedCategory])
                    && !isset($skipCategories[$forcedCategory])
                    && !in_array($forcedCategory, $categories, true)
                ) {
                    $categories[] = $forcedCategory;
                }
                continue;
            }
            $result = $this->susPatterns->detect($content, $clientIp, $context);
            if ($result['is_threat']) {
                foreach ($result['threats'] as $threat) {
                    $category = $threat['category'] ?? 'custom';
                    if (!in_array($category, $categories, true)
                        && !isset($skipCategories[$category])
                        && isset($enabledCategories[$category])
                    ) {
                        $categories[] = $category;
                    }
                }
            }
        }

        if ($categories === []) {
            return null;
        }

        $triggerInfo = 'threat categories: ' . implode(',', $categories);
        $this->stashBlock($request, 'Penetration patterns detected', $triggerInfo);
        foreach ($categories as $category) {
            $this->suspiciousCountStore->record($clientIp, $category);
        }

        if ($this->isPassiveMode()) {
            return null;
        }

        if ($this->config->enableIpBanning) {
            $count = $this->incrementCount($clientIp);
            $threshold = $this->config->autoBanThreshold;
            $duration = $this->config->autoBanDuration;
            foreach ($categories as $category) {
                $entry = $this->config->threatBanConfig[$category] ?? null;
                if ($entry !== null) {
                    $threshold = $entry['threshold'];
                    $duration = $entry['duration'];
                    break;
                }
            }
            if ($count >= $threshold && $this->ipBanManager !== null) {
                $this->ipBanManager->ban($clientIp, $duration, "penetration:{$categories[0]}");

                return $this->createErrorResponse(403, 'IP has been banned');
            }
        }

        return $this->createErrorResponse(400, 'Suspicious activity detected');
    }

    /**
     * Every request surface scanned with the context of the value actually
     * being scanned, so the per-context gates in SusPatterns::buildRegexThreat
     * apply. The request body is routed through the form/multipart/JSON
     * extraction (port of guard_core/_utils/body_form_scan.py and
     * body_json_scan.py): urlencoded bodies scan as field name/value pairs
     * with the request_body:form_field context, multipart bodies as part
     * entries with the request_body:multipart_field context (binary-dense
     * file payloads reduced to binary islands via
     * detection_binary_min_run_length), JSON-content-type bodies as ordered
     * JSON walks (mongo-operator keys reported straight from the walk, keys
     * as plain request_body components, leaves as request_body values,
     * depth-capped subtrees as compact serializations), and everything else
     * as the one raw body. Query parameters and headers scan with their own
     * context; any of those values that itself parses as embedded JSON scans
     * leaf-first with the :embedded_json context suffix before the raw
     * value.
     *
     * Exclusion sets mirror the reference's config surface:
     * excluded_detection_params skips a query parameter's whole pair
     * (`key.lower() in excluded_params` in _scan_query_params), and
     * excluded_detection_body_fields skips urlencoded pairs and multipart
     * parts by field name and whole JSON subtrees by key at any nesting
     * depth. Query and header values thread the body-field exclusion into
     * their embedded-JSON walks like the reference's
     * _scan_query_param_value / _scan_normal_header_component.
     *
     * Headers listed in the excluded-header surface (the hardcoded proxy
     * identity set merged with excluded_detection_headers, resolved through
     * HeaderExclusions) are not skipped outright: like the reference's
     * _scan_excluded_header_component they keep scanning with every enabled
     * category except the ones the value is known to false-positive (ssrf
     * for address-carrying headers and address-chain values), carried as the
     * entry's skip-category set and filtered in check().
     *
     * Each entry is [content, context, forcedCategory, skipCategories].
     *
     * @return list<array{string, string, ?string, array<string, true>}>
     */
    /**
     * Mirrors _resolve_enabled_categories: a non-null route category set
     * replaces the global one (an empty list disables every category).
     *
     * @return array<string, true>
     */
    private function resolveEnabledCategories(?RouteConfig $routeConfig): array
    {
        $routeCategories = $routeConfig?->enabledDetectionCategories;

        return $routeCategories !== null
            ? array_fill_keys($routeCategories, true)
            : $this->config->enabledDetectionCategories;
    }

    private function scanValues(GuardRequest $request): array
    {
        $values = [[$request->urlPath(), 'url_path', null, []]];
        $routeConfig = $request->state()->routeConfig;
        // The per-route exclusion surfaces, resolved with the reference's
        // _resolve_* helpers (guard_core/_utils/detection_config.py): a
        // non-null route set replaces the global one, the header set always
        // merges defaults + global + route, and a non-null route
        // detection_scan_body overrides the global default.
        $routeParams = $routeConfig?->excludedDetectionParams;
        $excludedParams = $routeParams !== null ? array_fill_keys($routeParams, true) : $this->config->excludedDetectionParams;
        $routeBodyFields = $routeConfig?->excludedDetectionBodyFields;
        $excludedBodyFields = $routeBodyFields !== null ? array_fill_keys($routeBodyFields, true) : $this->config->excludedDetectionBodyFields;
        $routeExcludedHeaders = $routeConfig?->excludedDetectionHeaders ?? [];
        $excludedHeaders = HeaderExclusions::mergedExcludedNames(array_merge(
            $this->config->excludedDetectionHeaders,
            array_fill_keys($routeExcludedHeaders, true)
        ));
        $enabledCategories = $this->resolveEnabledCategories($routeConfig);
        $scanBody = $routeConfig?->detectionScanBody ?? $this->config->detectionScanBody;
        foreach ($request->queryParams() as $name => $value) {
            if (isset($excludedParams[strtolower((string) $name)])) {
                continue;
            }
            foreach ((array) $value as $single) {
                foreach ($this->scannedValue((string) $single, 'query_param', $excludedBodyFields) as $entry) {
                    $values[] = $entry;
                }
            }
        }
        $headers = $request->headers();
        foreach ($headers->all() as $name => $value) {
            if (isset($this->config->logSensitiveHeaders[strtolower($name)])) {
                continue;
            }
            $skipCategories = isset($excludedHeaders[strtolower((string) $name)])
                ? HeaderExclusions::skipCategories((string) $name, (string) $value)
                : [];
            foreach ($this->scannedValue((string) $value, 'header', $excludedBodyFields, $skipCategories) as $entry) {
                $values[] = $entry;
            }
        }
        $body = $request->body();
        if ($body !== '' && $scanBody) {
            $contentType = $headers->get('content-type') ?? '';
            foreach (BodyFormScan::bodyScanEntries($body, $contentType, $this->config->detectionBinaryMinRunLength, $excludedBodyFields) as [$content, $context, $forcedCategory]) {
                $values[] = [$content, $context, $forcedCategory, []];
            }
        }

        return $values;
    }

    /**
     * One query or header value: an embedded JSON value walks leaf-first
     * with the context plus the :embedded_json suffix (the reference's
     * embedded-JSON check runs for every non-body context, with the
     * excluded body fields skipping whole JSON subtrees by key), then the
     * raw value scans with the plain context. The skip-category set rides
     * on every produced entry so the excluded-header ssrf filter applies to
     * the walk leaves and the raw value alike.
     *
     * @param array<string, true> $excludedBodyFields
     * @param array<string, true> $skipCategories
     * @return list<array{string, string, null, array<string, true>}>
     */
    private function scannedValue(string $value, string $context, array $excludedBodyFields = [], array $skipCategories = []): array
    {
        $root = JsonWalk::parse($value);
        if ($root === null) {
            return [[$value, $context, null, $skipCategories]];
        }
        $entries = JsonWalk::walkEntries($root, $context . JsonWalk::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX, $excludedBodyFields);
        foreach ($entries as $i => [$leaf, $leafContext, $leafForced]) {
            $entries[$i] = [$leaf, $leafContext, $leafForced, $skipCategories];
        }
        $entries[] = [$value, $context, null, $skipCategories];

        return $entries;
    }

    private function incrementCount(string $ip): int
    {
        $count = ($this->suspiciousCounts[$ip] ?? 0) + 1;
        unset($this->suspiciousCounts[$ip]);
        $this->suspiciousCounts[$ip] = $count;
        while (count($this->suspiciousCounts) > self::MAX_TRACKED_IPS) {
            $oldest = array_key_first($this->suspiciousCounts);
            unset($this->suspiciousCounts[$oldest]);
        }

        return $count;
    }
}
