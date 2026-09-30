<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;
use RenzoFranceschini\GuardCore\Detection\Redos\ScanGuard;
use RenzoFranceschini\GuardCore\Detection\Redos\ScanResult;
use RenzoFranceschini\GuardCore\Support\Generated\PatternData;
use RenzoFranceschini\GuardCore\Support\Text;

final class SusPatterns
{
    private const EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX = ':embedded_json';
    private const KNOWN_CONTEXTS = ['query_param', 'header', 'url_path', 'request_body', 'unknown'];
    private const COMPILER_TIMEOUT = 2.0;
    private const MAX_CONTENT_LENGTH = 10000;

    /**
     * Subject-size gate for the size-gated line-walk pattern family
     * (PatternData::SIZE_GATED_PATTERN_INDICES). Those patterns anchor at \A
     * and walk the subject (per character, or per path segment), so PCRE2
     * consumes JIT stack proportional to the walked line and a long enough
     * single-line subject exhausts the stack, aborting detection of benign
     * traffic with a PregFailure (fail-secure turns that into a 500).
     * Measured on php:8.3-cli with stock ini, pcre.jit=1: the line-walk shapes
     * fail from ~24.5KB subjects, the \A-anchored path-walk segment loops fail
     * from ~16.4KB subjects once a trailing target follows ~16KB of path
     * segments ("a/" repeated, 2 bytes per walked segment, is the
     * stack-densest input), which is the binding cliff at 16392 bytes.
     * Under pcre.jit=0 the same shapes fail from ~100KB
     * (PREG_RECURSION_LIMIT_ERROR). 15360 (15 KiB) sits ~6% below the
     * segment-loop cliff, so the gate holds under either pcre.jit setting and
     * no view subject that can still exhaust the stack reaches a gated preg
     * call, while staying above the largest frozen conformance corpus content
     * (14725 bytes), so no corpus outcome changes. Walk and segment patterns
     * are line-scoped, so skipping above the gate only forgoes their coverage
     * on very long single-line subjects; all other patterns still scan.
     */
    public const GATED_PATTERN_MAX_SUBJECT_BYTES = 15360;

    private const LDAP_NULL_BYTE_ATTR_TAIL = '\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)';
    private const LDAP_NULL_BYTE_DECODED_ATTR_TAIL = '\\*\\)+\\x00';

    /**
     * Test hook: disabling the gate mirrors the Python honesty test's
     * monkeypatch of match_is_binary_dense to always False, proving the
     * frozen noise-prone registry is minimal (every registered pattern
     * really does fire on random binary noise when the gate is off).
     */
    public static bool $binaryNoiseGateEnabled = true;

    /**
     * Test hook: overrides the compiler timeout (seconds) the section 04
     * scan gates use, the equivalent of the Python tests constructing the
     * engine with a custom detection_compiler_timeout. Null keeps the
     * shipped default.
     */
    public static ?float $compilerTimeoutOverride = null;

    private static function compilerTimeout(): float
    {
        return self::$compilerTimeoutOverride ?? self::COMPILER_TIMEOUT;
    }

    private Preprocessor $preprocessor;
    private float $semanticThreshold;

    public function __construct(float $semanticThreshold = 0.7)
    {
        $this->preprocessor = new Preprocessor();
        $this->semanticThreshold = $semanticThreshold;
    }

    public static function normalizeContext(?string $context): string
    {
        if ($context === null) {
            return 'unknown';
        }
        $normalized = explode(':', $context, 2)[0];

        return in_array($normalized, self::KNOWN_CONTEXTS, true) ? $normalized : 'unknown';
    }

    public static function resolvePatternWeight(string $pattern, string $category): float
    {
        if (isset(PatternData::WEIGHT_OVERRIDES[$pattern])) {
            return PatternData::WEIGHT_OVERRIDES[$pattern];
        }

        return 1.0;
    }

    private static function isRawViewSource(string $source): bool
    {
        return in_array($source, PatternData::RAW_VIEW_SOURCES, true);
    }

    private static function isUrlDecodedViewSource(string $source): bool
    {
        return in_array($source, PatternData::URL_DECODED_VIEW_SOURCES, true);
    }

    private static function isReconRawViewSource(string $source): bool
    {
        return in_array($source, PatternData::RECON_RAW_VIEW_PATTERN_SOURCES, true);
    }

    private static function patternExcludedFromView(string $source, string $viewMode): bool
    {
        if ($viewMode === 'raw') {
            // Recon rows also run on the raw view: the processed views fold
            // LDAP hex escapes ("\de" -> "Þ") before the pattern tables run,
            // so separator-prefixed probes such as "\default" only survive
            // there (upstream DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES).
            return self::isUrlDecodedViewSource($source)
                || !(self::isRawViewSource($source) || self::isReconRawViewSource($source));
        }
        if ($viewMode === 'url_decoded') {
            return self::isRawViewSource($source) || !self::isUrlDecodedViewSource($source);
        }
        if ($viewMode === 'processed') {
            return self::isRawViewSource($source) || self::isUrlDecodedViewSource($source);
        }

        return false;
    }

    public static function sanitizeForReporting(string $value): string
    {
        $out = '';
        $len = Text::len($value);
        for ($i = 0; $i < $len; $i++) {
            $ch = Text::slice($value, $i, 1);
            $cp = Text::ord($ch);
            if ($cp >= 0xdc80 && $cp <= 0xdcff) {
                $out .= '\\x' . str_pad(dechex($cp - 0xdc00), 2, '0', STR_PAD_LEFT);
                continue;
            }
            $out .= $ch;
        }

        return $out;
    }

    /**
     * Keep only the raw-view threats whose (pattern, match text) pair the
     * processed views have not already recorded. Threat and matched-pattern
     * lists are parallel (one append per match), so a raw-view sighting of a
     * pattern over text the processed views already matched is the same
     * evidence and must not inflate the threat score (upstream
     * `_drop_view_duplicate_threats`).
     *
     * @param list<array<string, mixed>> $seenThreats
     * @param list<array<string, mixed>> $newThreats
     * @return list<array<string, mixed>>
     */
    private static function dropViewDuplicateThreats(array $seenThreats, array $newThreats): array
    {
        $seen = [];
        foreach ($seenThreats as $threat) {
            $seen[$threat['pattern'] . "\x00" . $threat['match']] = true;
        }
        $kept = [];
        foreach ($newThreats as $threat) {
            $key = $threat['pattern'] . "\x00" . $threat['match'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $kept[] = $threat;
        }

        return $kept;
    }

    private function buildRegexThreat(string $source, array $match, string $category, string $content, string $validatorContext, ?array $binaryPrefix): ?array
    {
        $kind = PatternData::VALIDATOR_KINDS[$source] ?? null;
        if ($kind !== null && !self::validatorAccepts($kind, $content, $match, $validatorContext, $source)) {
            return null;
        }

        // Recon leading-separator gate (guard-core, upstream commit 79818055):
        // whole-value recon rows whose leading path separator is optional match
        // bare words such as "default" or "README.md" outside a URL path.
        // Reject the match unless the scanned value's normalized context is
        // path-like (url_path, unknown) or the matched text itself starts with
        // a path separator. Keyed on the context of the value actually being
        // scanned (request_body/unknown skip the pattern-declared context
        // filter elsewhere), after the candidate rejection validators and
        // before the binary noise gate, like the Python engine.
        if (in_array($source, PatternData::RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES, true)
            && !self::reconPathValueIsProbe($match['text'], self::normalizeContext($validatorContext))) {
            return null;
        }

        // Binary noise gate (guard-core 4.0.3): after the candidate rejection
        // validators, discard matches from the noise-prone registry when the
        // surrounding window is binary-content dense. Signature patterns are
        // never gated.
        if ($binaryPrefix !== null
            && self::$binaryNoiseGateEnabled
            && in_array($source, PatternData::NOISE_PRONE_PATTERN_SOURCES, true)
            && BinaryPrefix::matchIsBinaryDense($binaryPrefix, $match['start'], $match['end'])) {
            return null;
        }

        return [
            'type' => 'regex',
            'pattern' => $source,
            'match' => self::sanitizeForReporting($match['text']),
            'position' => Text::bytesToCp($content, $match['start']),
            'category' => $category,
            'weight' => self::resolvePatternWeight($source, $category),
        ];
    }

    /**
     * Port of _recon_path_value_is_probe: a match counts as a probe when the
     * scanned value lives in a path-like context (url_path, unknown) or the
     * matched text itself begins with a path separator. The context arrives
     * already normalized plus the optional :embedded_json suffix, so it is
     * normalized again to strip the suffix.
     */
    private static function reconPathValueIsProbe(string $matchedText, string $normalizedContext): bool
    {
        if (in_array($normalizedContext, ['url_path', 'unknown'], true)) {
            return true;
        }

        return str_starts_with($matchedText, '/') || str_starts_with($matchedText, '\\');
    }

    private static function validatorAccepts(string $kind, string $content, array $match, string $context, string $source): bool
    {
        return match ($kind) {
            'legacy_ipv4' => LdapIpv4::legacyIpv4MatchIsBlocked($match),
            'ldap_wildcard_chain' => LdapIpv4::wildcardChainIsInjection($content, $match, $source),
            'ldap_paren_conjunction' => LdapIpv4::parenConjunctionIsInjection($content, $match, $source),
            'glued_backtick' => ShellValidators::gluedBacktickPairIsInjection($content, $match, $context),
            'source_extension_path' => !str_ends_with($context, self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX),
            'dollar_substitution' => ShellValidators::dollarSubstitutionPairIsInjection($content, $match, $context),
            'brace_expansion' => ShellValidators::braceExpansionIsDangerousCommand($content, $match),
            'quote_splice' => ShellValidators::quoteSpliceTokenIsDangerousCommand($content, $match),
            'glob' => ShellValidators::globWildcardTokenIsDangerousCommand($content, $match, $context),
            'pickle_generic' => Pickle::globalCandidateIsInjection($content, $match),
            default => true,
        };
    }

    private static function fileUploadKind(string $source): string
    {
        if (str_contains($source, '%00|')) {
            return 'file_upload_truncation';
        }
        if (str_contains($source, '(?:\\x00|;)')) {
            return 'file_upload_decoded_truncation';
        }
        if (str_contains($source, 'docx')) {
            return 'file_upload_double';
        }

        return 'file_upload_dangerous';
    }

    private static function matchesForPattern(string $source, string $content): array
    {
        $matcherKind = PatternData::MATCHER_KINDS[$source] ?? null;
        if ($matcherKind !== null) {
            return match ($matcherKind) {
                'load_file' => Matchers::loadFileScanMatches($content, $source),
                'cmd_dollar' => Matchers::cmdInjectionDollarScanMatches($content, $source),
                'file_upload' => Matchers::fileUploadScanMatches($content, self::fileUploadKind($source)),
                'template_curly_keyword' => Matchers::templateKeywordMatches($content, $source, '{{', '}}'),
                'template_dollar' => Matchers::templateExpressionMatches($content, $source, 'dollar'),
                'template_curly_call' => Matchers::templateExpressionMatches($content, $source, 'curly'),
                'template_percent' => Matchers::templateKeywordMatches($content, $source, '{%', '%}'),
                'template_asp' => Matchers::templateExpressionMatches($content, $source, 'asp'),
                'template_hash' => Matchers::templateExpressionMatches($content, $source, 'hash'),
                'glob' => Matchers::globWildcardScanMatches($content, $source),
                default => Preg::allMatches($source, $content),
            };
        }

        $finderKind = PatternData::FINDER_KINDS[$source] ?? null;
        if ($finderKind !== null) {
            return match ($finderKind) {
                'shell_dash_c' => Matchers::cmdInjectionShellDashCFinditer($content, $source),
                'ldap_null_attr_raw' => Matchers::ldapNullByteAttrFinditer($content, $source, self::LDAP_NULL_BYTE_ATTR_TAIL),
                'ldap_null_attr_decoded' => Matchers::ldapNullByteAttrFinditer($content, $source, self::LDAP_NULL_BYTE_DECODED_ATTR_TAIL),
                'quote_splice' => Matchers::quoteSpliceFinditer($content, $source),
                'pickle_generic' => Matchers::pickleGlobalGenericFinditer($content, $source),
                'xml_public_dtd' => XmlXxe::xmlXxePublicExternalDtdFinditer($content, $source),
                default => Preg::allMatches($source, $content),
            };
        }

        $bounds = PatternData::SCAN_WINDOW_BOUNDS[$source] ?? null;
        if ($bounds !== null) {
            if ($source === '<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>') {
                return XmlXxe::xmlSystemFinditer($content);
            }
            if ($source === '<!DOCTYPE[^>\\[]*\\[[\\s\\S]*?<!ENTITY') {
                return XmlXxe::xmlInternalEntityFinditer($content);
            }
            $matches = [];
            foreach ($bounds as [$prefix, $terminator]) {
                foreach (Matchers::boundedFindIter($content, $source, $prefix, $terminator) as $m) {
                    $matches[] = $m;
                }
            }

            return $matches;
        }

        return Preg::allMatches($source, $content);
    }

    private function firstAcceptedRegexThreat(string $source, string $content, string $category, string $validatorContext, ?array $binaryPrefix): ?array
    {
        foreach (self::matchesForPattern($source, $content) as $match) {
            $threat = $this->buildRegexThreat($source, $match, $category, $content, $validatorContext, $binaryPrefix);
            if ($threat !== null) {
                return $threat;
            }
        }

        return null;
    }

    /**
     * Byte length of the first line of $content. The size-gated patterns
     * anchor at \A and their walks stop at the first newline, so this is the
     * subject length that drives their PCRE2 stack consumption.
     */
    private static function firstLineByteLength(string $content): int
    {
        $nl = strpos($content, "\n");

        return $nl === false ? strlen($content) : $nl;
    }

    private function checkRegexPatterns(string $content, string $context, string $viewMode): array
    {
        $threats = [];
        $matchedPatterns = [];
        $timeouts = [];
        $normalized = self::normalizeContext($context);
        $validatorContext = str_ends_with($context, self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
            ? $normalized . self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX
            : $normalized;
        $skipFilter = $normalized === 'unknown' || $normalized === 'request_body';
        $gatedLineBytes = self::firstLineByteLength($content);
        // Built once per scanned string (O(n)); the density query is O(1) per
        // match (guard-core 4.0.3 binary noise gate).
        $binaryPrefix = BinaryPrefix::build($content);

        foreach (PatternData::PATTERNS as $index => [$source, $contexts, $category]) {
            if (self::patternExcludedFromView($source, $viewMode)) {
                continue;
            }
            if (!$skipFilter && !in_array($normalized, $contexts, true)) {
                continue;
            }
            // Gated = skip the preg call for this view/subject (no match
            // contribution), never a failure: large subjects must complete
            // detection instead of tripping PREG_JIT_STACKLIMIT_ERROR.
            if ($gatedLineBytes >= self::GATED_PATTERN_MAX_SUBJECT_BYTES
                && in_array($index, PatternData::SIZE_GATED_PATTERN_INDICES, true)) {
                continue;
            }
            $startNs = hrtime(true);
            [$threat, $timeoutOccurred] = $this->scanPattern($source, $category, $content, $validatorContext, $binaryPrefix);
            $elapsedSeconds = (hrtime(true) - $startNs) / 1e9;
            if ($timeoutOccurred) {
                $timeouts[] = $source;
                self::logPatternTimeout($source);
                if ($threat === null) {
                    $threat = self::buildTimeoutThreat($source, $category, $elapsedSeconds);
                }
            }
            if ($threat !== null) {
                $threats[] = $threat;
                $matchedPatterns[] = $source;
            }
        }

        return [$threats, $matchedPatterns, $timeouts];
    }

    /**
     * The exact reference timeout semantics (_suspatterns_regex.py): a
     * timed-out scan emits a pattern_timeout threat
     * ("threats-logged-and-miss") unless a real threat was already found,
     * so an engine that could not finish a scan fails closed instead of
     * silently passing the value. Shape mirrors _build_timeout_threat.
     *
     * @return array<string, mixed>
     */
    private static function buildTimeoutThreat(string $source, string $category, float $executionTimeSeconds): array
    {
        return [
            'type' => 'pattern_timeout',
            'pattern' => $source,
            'match' => '',
            'position' => 0,
            'execution_time' => $executionTimeSeconds,
            'category' => $category,
            'weight' => self::resolvePatternWeight($source, $category),
        ];
    }

    private static function logPatternTimeout(string $source): void
    {
        error_log('[guard_core] Pattern timeout: ' . substr($source, 0, 50)
            . (strlen($source) > 50 ? '...' : ''));
    }

    /**
     * One pattern's scan under the section 04 safety gates, with the
     * reference's per-pattern classification and its distinct timeout
     * semantics (_check_regex_pattern):
     *
     * - scan-window bounded patterns (SCAN_WINDOW_BOUNDS) run unguarded:
     *   bounded by construction, they carry no timeout arm in the reference
     *   either;
     * - windowed finders (FINDER_KINDS) run under the full compiler timeout
     *   and the backtrack budget, like the reference's pool-submitted
     *   finders; an engine-budget or deadline trip reports a timeout;
     * - plain patterns run under the backtrack budget with the canary probe
     *   in front (ScanGuard::probeBeforeScan, the arbiter's cost decision
     *   applied to the value being scanned) and the reference's 0.9x-timeout
     *   heuristic arm behind: no accepted threat and a wall clock at or over
     *   0.9x the compiler timeout is a timeout. PREG_BACKTRACK_LIMIT_ERROR
     *   and PREG_RECURSION_LIMIT_ERROR trips fail closed as timeouts; any
     *   other preg failure keeps the engine's fail-secure behavior.
     *
     * @return array{0: array<string, mixed>|null, 1: bool} [threat, timeoutOccurred]
     */
    private function scanPattern(string $source, string $category, string $content, string $validatorContext, ?array $binaryPrefix): array
    {
        if (isset(PatternData::SCAN_WINDOW_BOUNDS[$source])) {
            return [$this->firstAcceptedRegexThreat($source, $content, $category, $validatorContext, $binaryPrefix), false];
        }
        if (isset(PatternData::FINDER_KINDS[$source])) {
            $result = $this->guardedThreat($source, $category, $content, $validatorContext, $binaryPrefix, self::compilerTimeout());
            if ($result->timedOut) {
                return [null, true];
            }

            return [$result->value, false];
        }

        $canaryTripped = false;
        if (!isset(PatternData::MATCHER_KINDS[$source]) && strlen($content) > 8192) {
            $compiled = Prefilters::compileForValidation($source);
            if (is_string($compiled)) {
                $canaryTripped = ScanGuard::probeBeforeScan($compiled, $content, 0.9 * self::compilerTimeout());
            }
        }
        if ($canaryTripped) {
            return [null, true];
        }
        $result = $this->guardedThreat($source, $category, $content, $validatorContext, $binaryPrefix, null);
        if ($result->timedOut) {
            return [null, true];
        }
        if ($result->value === null && $result->elapsedSeconds !== null
            && $result->elapsedSeconds >= 0.9 * self::compilerTimeout()) {
            return [null, true];
        }

        return [$result->value, false];
    }

    private function guardedThreat(
        string $source,
        string $category,
        string $content,
        string $validatorContext,
        ?array $binaryPrefix,
        ?float $deadlineSeconds
    ): ScanResult {
        return ScanGuard::runBounded(
            fn (): ?array => $this->firstAcceptedRegexThreat($source, $content, $category, $validatorContext, $binaryPrefix),
            ScanGuard::STOCK_BACKTRACK_BUDGET,
            $deadlineSeconds
        );
    }

    private function checkDecodedViewPathTraversal(string $processedContent, string $content, string $context): ?array
    {
        $rawViewContent = $this->preprocessor->preprocessSignalPreserving($content);
        $decodedViewContent = $processedContent;
        $decodedMatches = Preg::allMatches(PatternData::DECODED_PATH_TRAVERSAL_RE, $decodedViewContent);
        $rawCount = count(Preg::allMatches(PatternData::DECODED_PATH_TRAVERSAL_RE, $rawViewContent));
        if (count($decodedMatches) <= $rawCount) {
            return null;
        }
        $match = $decodedMatches[0];

        return [
            'type' => 'regex',
            'pattern' => PatternData::DECODED_PATH_TRAVERSAL_RE,
            'match' => self::sanitizeForReporting($match['text']),
            'position' => Text::bytesToCp($decodedViewContent, $match['start']),
            'category' => 'path_traversal',
            'weight' => self::resolvePatternWeight(PatternData::DECODED_PATH_TRAVERSAL_RE, 'path_traversal'),
        ];
    }

    private function checkUrlDecodedViewPatterns(string $content, string $context, string $precomputedDecoded, array|bool $decodeBudgetExhausted): array
    {
        $urlDecodedViewContent = Truncation::truncateSafely($precomputedDecoded, $this->preprocessor);
        [$threats, $matched, $timeouts] = $this->checkRegexPatterns($urlDecodedViewContent, $context, 'url_decoded');

        return [$threats, $matched, $timeouts, $decodeBudgetExhausted];
    }

    private function checkShortBase64AdditiveViewPatterns(string $content, string $context): array
    {
        $additiveViewContent = $this->preprocessor->preprocessShortBase64AdditiveView($content);
        if ($additiveViewContent === '') {
            return [[], [], []];
        }

        return $this->checkRegexPatterns($additiveViewContent, $context, 'all');
    }

    private function checkSemanticThreats(string $content, string $rawContent): array
    {
        if (Semantic::looksLikeBinaryContent($rawContent)) {
            return [[], 0.0];
        }
        $semanticBudget = min(Text::len($content), self::MAX_CONTENT_LENGTH);
        $analysis = Semantic::analyze(Text::slice($content, 0, $semanticBudget));
        $semanticScore = Semantic::getThreatScore($analysis);
        $threats = [];
        if ($semanticScore > $this->semanticThreshold) {
            foreach ($analysis['attack_probabilities'] as $attackType => $probability) {
                if ($probability >= $this->semanticThreshold) {
                    $threats[] = [
                        'type' => 'semantic',
                        'attack_type' => $attackType,
                        'probability' => $probability,
                        'analysis' => $analysis,
                    ];
                }
            }
            if ($threats === [] && $semanticScore >= $this->semanticThreshold) {
                $threats[] = [
                    'type' => 'semantic',
                    'attack_type' => 'suspicious',
                    'threat_score' => $semanticScore,
                    'analysis' => $analysis,
                ];
            }
        }

        return [$threats, $semanticScore];
    }

    public function detect(string $content, string $ip, string $context): array
    {
        $originalContent = $content;
        $decodeBudgetExhausted = [false];
        [$processedContent, $precomputedDecoded] = $this->preprocessor->preprocessWithDecoded($content, $decodeBudgetExhausted);

        [$regexThreats, $matchedPatterns, $timeouts] = $this->checkRegexPatterns($processedContent, $context, 'processed');

        $rawViewContent = $this->preprocessor->preprocessSignalPreserving($content);
        [$rawThreats, $rawMatched, $rawTimeouts] = $this->checkRegexPatterns($rawViewContent, $context, 'raw');
        // A (pattern, match) the processed views already recorded is the same
        // evidence; drop it so a row matching both views counts once. Raw-view
        // timeout sources are deduplicated the same way.
        $rawThreats = self::dropViewDuplicateThreats($regexThreats, $rawThreats);
        $rawMatched = array_column($rawThreats, 'pattern');
        $regexThreats = array_merge($regexThreats, $rawThreats);
        $matchedPatterns = array_merge($matchedPatterns, $rawMatched);
        $timeouts = array_merge($timeouts, array_values(array_diff($rawTimeouts, $timeouts)));

        $decodedViewThreat = $this->checkDecodedViewPathTraversal($processedContent, $content, $context);
        if ($decodedViewThreat !== null) {
            $regexThreats[] = $decodedViewThreat;
            $matchedPatterns[] = $decodedViewThreat['pattern'];
        }

        [$urlDecodedThreats, $urlDecodedMatched, $urlDecodedTimeouts, $urlDecodedBudgetExhausted] =
            $this->checkUrlDecodedViewPatterns($content, $context, $precomputedDecoded, $decodeBudgetExhausted);
        $regexThreats = array_merge($regexThreats, $urlDecodedThreats);
        $matchedPatterns = array_merge($matchedPatterns, $urlDecodedMatched);
        $timeouts = array_merge($timeouts, $urlDecodedTimeouts);

        if ($decodeBudgetExhausted[0] || $urlDecodedBudgetExhausted[0]) {
            $exhaustionThreat = [
                'type' => 'regex',
                'pattern' => 'decode_budget_exhausted',
                'match' => 'decode_budget_exhausted',
                'position' => 0,
                'category' => 'custom',
                'weight' => 1.0,
            ];
            $regexThreats[] = $exhaustionThreat;
            $matchedPatterns[] = $exhaustionThreat['pattern'];
        }

        [$shortBase64Threats, $shortBase64Matched, $shortBase64Timeouts] = $this->checkShortBase64AdditiveViewPatterns($content, $context);
        $regexThreats = array_merge($regexThreats, $shortBase64Threats);
        $matchedPatterns = array_merge($matchedPatterns, $shortBase64Matched);
        $timeouts = array_merge($timeouts, $shortBase64Timeouts);

        [$semanticThreats] = $this->checkSemanticThreats($processedContent, $originalContent);

        $threats = array_merge($regexThreats, $semanticThreats);

        $anomaly = 0.0;
        foreach ($regexThreats as $t) {
            $anomaly += $t['weight'] ?? 1.0;
        }
        $isThreat = $anomaly >= 1.0 || count($semanticThreats) > 0;

        $semanticMax = 0.0;
        foreach ($semanticThreats as $t) {
            $semanticMax = max($semanticMax, $t['probability'] ?? $t['threat_score'] ?? 0.0);
        }
        $threatScore = ($regexThreats === [] && $semanticThreats === []) ? 0.0 : min(max($anomaly, $semanticMax), 1.0);

        usort($threats, self::canonicalThreatSort(...));

        return [
            'is_threat' => $isThreat,
            'threat_score' => round($threatScore, 6),
            'threats' => $threats,
            'original_length' => Text::len($originalContent),
            'processed_length' => Text::len($processedContent),
            'detection_method' => 'enhanced',
            'timeouts' => $timeouts,
        ];
    }

    public static function canonicalThreatSort(array $a, array $b): int
    {
        $categoryA = $a['category'] ?? $a['attack_type'] ?? '';
        $categoryB = $b['category'] ?? $b['attack_type'] ?? '';
        $ka = [$categoryA, $a['pattern'] ?? '', $a['position'] ?? 0, $a['type'] ?? ''];
        $kb = [$categoryB, $b['pattern'] ?? '', $b['position'] ?? 0, $b['type'] ?? ''];

        return $ka <=> $kb;
    }
}
