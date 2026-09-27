<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Ordered JSON walk (parity with guard_core/_utils/body_json_scan.py and
 * embedded_json_scan.py, mirroring the Go engine's guardcore/jsonwalk.go).
 *
 * The reference engine parses with json.loads (dict insertion order, first
 * position kept and last value kept for duplicate keys) and walks the tree
 * depth-first in insertion order: for each object entry the key is checked
 * against the mongo-operator-key registry (direct nosql hit reported
 * straight from the walk, unfiltered by a pattern scan) and otherwise
 * scanned as a plain request_body component; then the entry value descends.
 * Objects and arrays whose frame depth reaches the cap (32) are serialized
 * back to compact JSON (json.dumps separators=(",", ":"), ensure_ascii=
 * False) and scanned as one text value. Scalar leaves scan str(value).
 *
 * Values parsed out of a form field, multipart entry, query parameter or
 * header string walk with the original context plus the ":embedded_json"
 * suffix, and such a leaf string that itself parses as a JSON object or
 * array walks again with another suffix, exactly like the reference's
 * embedded-JSON check. The top-level JSON body walk keeps the plain
 * request_body context and never re-parses leaf strings (the reference
 * skips the embedded check when the context is exactly request_body).
 *
 * Parse model: json_decode in object mode returns stdClass for JSON objects
 * (insertion-ordered properties, duplicate keys keeping the first position
 * and the last value, like a Python dict) and plain lists for JSON arrays,
 * so objects and arrays are distinguishable. Any parse failure - malformed
 * input, trailing data, a scalar root, or nesting past PHP's 512-level
 * decoder cap - returns null and the caller falls back to the blob or raw
 * value scan, like the reference.
 */
final class JsonWalk
{
    public const EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX = ':embedded_json';

    /**
     * The reference _scan_body_field trigger prefix for a named field
     * ("Request body field 'x': "); an empty label (a top-level leaf) scans
     * as the plain "Request body: " component and carries no prefix here.
     */
    public static function bodyFieldLabel(string $label): string
    {
        return $label === '' ? '' : "Request body field '{$label}': ";
    }

    /** Objects and arrays at this frame depth serialize compactly (Python _DEFAULT_MAX_JSON_DEPTH). */
    public const DEPTH_CAP = 32;

    private const REQUEST_BODY_CONTEXT = 'request_body';

    /** _MONGO_OPERATOR_KEY_RE from body_json_scan.py. */
    private const MONGO_OPERATOR_KEY_RE = '/^\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|mod|options|where|regex|expr|function|elemMatch)$/';

    /**
     * Parse a JSON object or array root; null on any failure (the caller
     * falls back to the blob or raw value scan).
     */
    public static function parse(string $s): object|array|null
    {
        $decoded = json_decode($s, false, 512);
        if (!is_object($decoded) && !is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    /**
     * The scan values of one JSON walk in the reference order:
     * [content, context, forcedCategory]. forcedCategory is 'nosql' for the
     * mongo-operator-key hits, which the pipeline reports without a pattern
     * scan (body_json_scan._mongo_operator_key_hit). $excludedBodyFields
     * mirrors body_json_scan's excluded_body_fields: an entry key matching
     * the set (case-insensitively) skips its whole subtree - the key does
     * not scan and the value never descends.
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, ?string}>
     */
    public static function walkEntries(object|array $root, string $context, array $excludedBodyFields = []): array
    {
        $allowLeafReparse = $context !== self::REQUEST_BODY_CONTEXT;
        $entries = [];
        $stack = [['isEntry' => false, 'node' => $root, 'label' => '', 'depth' => 1]];
        while ($stack !== []) {
            $frame = array_pop($stack);
            if ($frame['isEntry']) {
                $keyStr = $frame['key'];
                if (isset($excludedBodyFields[strtolower($keyStr)])) {
                    continue;
                }
                if (preg_match(self::MONGO_OPERATOR_KEY_RE, $keyStr) === 1) {
                    // The reference _mongo_operator_key_hit trigger message:
                    // the operator key plus the pattern source it matched.
                    $patternSource = "^\\\\\$(?:ne|gt|gte|lt|lte|eq|in|nin|nor|and|or|not|all|size|exists|type|mod|options|where|regex|expr|function|elemMatch)\$";
                    $entries[] = [$keyStr, self::REQUEST_BODY_CONTEXT, 'nosql', "JSON operator key '{$keyStr}': matched pattern '{$patternSource}'"];
                    continue;
                }
                $entries[] = [$keyStr, self::REQUEST_BODY_CONTEXT, null, "JSON key '{$keyStr}': "];
                $stack[] = ['isEntry' => false, 'node' => $frame['item'], 'label' => $keyStr, 'depth' => $frame['depth'] + 1];
                continue;
            }
            $node = $frame['node'];
            if (is_object($node)) {
                if ($frame['depth'] >= self::DEPTH_CAP) {
                    $entries[] = [self::serializeCompact($node), $context, null, self::bodyFieldLabel($frame['label'])];
                    continue;
                }
                $props = get_object_vars($node);
                $keys = array_keys($props);
                for ($i = count($keys) - 1; $i >= 0; $i--) {
                    $stack[] = ['isEntry' => true, 'key' => (string) $keys[$i], 'item' => $props[$keys[$i]], 'depth' => $frame['depth']];
                }
                continue;
            }
            if (is_array($node)) {
                if ($frame['depth'] >= self::DEPTH_CAP) {
                    $entries[] = [self::serializeCompact($node), $context, null, self::bodyFieldLabel($frame['label'])];
                    continue;
                }
                for ($i = count($node) - 1; $i >= 0; $i--) {
                    // List items inherit the container's label.
                    $stack[] = ['isEntry' => false, 'node' => $node[$i], 'label' => $frame['label'], 'depth' => $frame['depth'] + 1];
                }
                continue;
            }
            // Scalar leaf: a string that itself parses as a JSON object or
            // array walks again with another suffix when the walk context is
            // not the plain body context.
            if ($allowLeafReparse && is_string($node)) {
                $inner = self::parse($node);
                if ($inner !== null) {
                    foreach (self::walkEntries($inner, $context . self::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX, $excludedBodyFields) as $entry) {
                        $entries[] = $entry;
                    }
                    // Clean-parse fall-through (embedded_json_scan.py +
                    // _check_value_enhanced): when the nested walk reports
                    // nothing, the raw leaf string still scans with the walk
                    // context, so payloads confined to the raw text
                    // (duplicate-key remnants, structural text) still hit.
                    $entries[] = [$node, $context, null, self::bodyFieldLabel($frame['label'])];
                    continue;
                }
            }
            $entries[] = [self::scalarText($node), $context, null, self::bodyFieldLabel($frame['label'])];
        }

        return $entries;
    }

    /**
     * Python str() rendering of a decoded scalar: "True"/"False"/"None" for
     * bool/null, the decimal text for integers, the shortest round-trip
     * rendering for floats (Python str(float), which json_encode matches).
     */
    private static function scalarText(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'True' : 'False';
        }
        if ($value === null) {
            return 'None';
        }
        if (is_float($value)) {
            $encoded = json_encode($value);

            return $encoded === false ? (string) $value : $encoded;
        }

        return (string) $value;
    }

    /**
     * json.dumps(value, separators=(",", ":"), ensure_ascii=False) over the
     * parsed tree.
     */
    public static function serializeCompact(object|array|string|int|float|bool|null $node): string
    {
        if (is_object($node)) {
            $props = get_object_vars($node);
            if ($props === []) {
                return '{}';
            }
            $out = [];
            foreach ($props as $key => $value) {
                $out[] = self::jsonString((string) $key) . ':' . self::serializeCompact($value);
            }

            return '{' . implode(',', $out) . '}';
        }
        if (!is_array($node)) {
            return self::jsonScalarLiteral($node);
        }
        if ($node === []) {
            return '[]';
        }
        $out = [];
        foreach ($node as $value) {
            $out[] = self::serializeCompact($value);
        }

        return '[' . implode(',', $out) . ']';
    }

    private static function jsonScalarLiteral(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            $encoded = json_encode($value);

            return $encoded === false ? (string) $value : $encoded;
        }

        return self::jsonString($value);
    }

    /**
     * json.dumps(ensure_ascii=False) string escaping: quote, backslash and
     * the C0 controls; everything else stays literal UTF-8.
     */
    private static function jsonString(string $s): string
    {
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $ch = $s[$i];
            $out .= match ($ch) {
                '"' => '\\"',
                '\\' => '\\\\',
                "\n" => '\\n',
                "\r" => '\\r',
                "\t" => '\\t',
                "\x08" => '\\b',
                "\x0c" => '\\f',
                default => ord($ch) < 0x20 ? '\\u' . sprintf('%04x', ord($ch)) : $ch,
            };
        }

        return $out . '"';
    }
}
