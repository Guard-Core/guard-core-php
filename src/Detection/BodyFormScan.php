<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Form and multipart body extraction (port of guard_core/_utils/
 * body_form_scan.py, guard-core upstream commit 5f399234 and the body scan
 * routing it lives in).
 *
 * A urlencoded form body is split into field name/value pairs; a multipart
 * body is parsed per RFC 2046 with the same observable semantics as the
 * Python engine's email parser (preamble/epilogue discarded, the newline
 * before a boundary belongs to the boundary, folded header values keep the
 * embedded line break, quoted parameter values unescape backslash escapes).
 * Every extracted value carries its context so the per-context gates in
 * SusPatterns::buildRegexThreat apply per value, and binary-dense file-part
 * payloads are reduced to binary islands before scanning.
 *
 * JSON-content-type bodies route through the ordered JsonWalk (body keys
 * scan as plain request_body components with mongo-operator keys reported
 * straight from the walk, leaves scan as request_body values, and a body
 * past the parse cap falls back to the blob), and every field or entry
 * value that itself parses as JSON walks leaf-first with the
 * ":embedded_json" suffix before its raw value, exactly like the
 * reference's embedded-JSON check. $excludedBodyFields mirrors Python
 * excluded_detection_body_fields: urlencoded field names and multipart
 * part names skip their whole pair or part, and JSON object keys matching
 * the set (at any nesting depth) skip their whole subtree.
 */
final class BodyFormScan
{
    public const FORM_FIELD_CONTEXT = 'request_body:form_field';

    public const MULTIPART_FIELD_CONTEXT = 'request_body:multipart_field';

    /**
     * Scan values for a request body: urlencoded forms split into field
     * pairs, multipart bodies into part entries (binary-dense file payloads
     * reduced to islands), JSON-content-type bodies walked as ordered JSON
     * (mongo-operator keys, key components, leaves, compact serialization
     * at the depth cap), everything else scanned as the one raw body.
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, ?string}> [value, context, forcedCategory] in scan order
     */
    public static function bodyScanEntries(string $rawBody, string $contentType, int $binaryMinRunLength, array $excludedBodyFields = []): array
    {
        $lowered = strtolower($contentType);
        if (str_contains($lowered, 'application/x-www-form-urlencoded')) {
            return self::formScanEntries($rawBody, $excludedBodyFields);
        }
        if (str_contains($lowered, 'multipart/form-data')) {
            $entries = self::multipartScanEntries($rawBody, $contentType, $binaryMinRunLength, $excludedBodyFields);
            if ($entries !== null) {
                return $entries;
            }
        }
        if (str_contains($lowered, 'json')) {
            $root = JsonWalk::parse($rawBody);
            if ($root !== null) {
                return JsonWalk::walkEntries($root, 'request_body', $excludedBodyFields);
            }
        }

        return [[$rawBody, 'request_body', null, '']];
    }

    /**
     * Urlencoded form fields: the field name scans as a plain request_body
     * component, the value scans with the :form_field context after its
     * embedded JSON walk (mirroring parse_qsl with keep_blank_values). An
     * excluded field name skips its whole pair (body_form_scan.py's
     * `name.lower() in excluded_body_fields` guard).
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, ?string}>
     */
    public static function formScanEntries(string $rawBody, array $excludedBodyFields = []): array
    {
        $entries = [];
        foreach (self::parseQsl($rawBody) as [$name, $value]) {
            if (isset($excludedBodyFields[strtolower($name)])) {
                continue;
            }
            $entries[] = [$name, 'request_body', null, "Form field name '{$name}': "];
            foreach (self::embeddedJsonEntries($value, self::FORM_FIELD_CONTEXT, $excludedBodyFields) as $entry) {
                $entries[] = $entry;
            }
            $entries[] = [$value, self::FORM_FIELD_CONTEXT, null, "Request body field '{$name}': "];
        }

        return $entries;
    }

    /**
     * Multipart parts: the field label scans as a plain request_body
     * component, each entry value (filename, part headers, payload) scans
     * with the :multipart_field context after its embedded JSON leaves.
     * A part whose name matches the excluded set skips its whole part
     * (_scan_multipart_part's exclusion_key guard); a part without a name
     * has no exclusion key and is always scanned. Returns null when the
     * body is not multipart-parseable so the caller falls back to the
     * whole-body blob scan (Python _scan_blob_body).
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, ?string}>|null
     */
    public static function multipartScanEntries(string $rawBody, string $contentType, int $binaryMinRunLength, array $excludedBodyFields = []): ?array
    {
        $parts = self::multipartParts($rawBody, $contentType, $binaryMinRunLength);
        if ($parts === null) {
            return null;
        }
        $entries = [];
        foreach ($parts as [$exclusionKey, $label, $values]) {
            if ($exclusionKey !== null && isset($excludedBodyFields[strtolower($exclusionKey)])) {
                continue;
            }
            if ($values === []) {
                continue;
            }
            $entries[] = [$label, 'request_body', null, "Multipart field name '{$label}': "];
            foreach ($values as $value) {
                foreach (self::embeddedJsonEntries($value, self::MULTIPART_FIELD_CONTEXT, $excludedBodyFields) as $entry) {
                    $entries[] = $entry;
                }
                $entries[] = [$value, self::MULTIPART_FIELD_CONTEXT, null, "Request body field '{$label}': "];
            }
        }

        return $entries;
    }

    /**
     * Leaf part entries in document order: [exclusionKey, label, values[]].
     * Null when the root body carries no boundary delimiter at all (Python
     * StartBoundaryNotFoundDefect: is_multipart() stays False and the whole
     * body falls back to the blob scan).
     *
     * @return list<array{?string, string, list<string>}>|null
     */
    public static function multipartParts(string $rawBody, string $contentType, int $binaryMinRunLength): ?array
    {
        $mediaType = self::mediaType($contentType);
        if ($mediaType === null || !str_starts_with($mediaType, 'multipart/')) {
            return null;
        }
        $boundary = self::boundaryOf($contentType);
        if ($boundary === null) {
            return null;
        }
        $segments = self::splitSegments($rawBody, $boundary);
        if ($segments === null) {
            return null;
        }
        $parts = [];
        foreach ($segments as $lines) {
            self::collectSegmentParts($lines, $binaryMinRunLength, $parts);
        }

        return $parts;
    }

    /**
     * Split a multipart chunk into the lines (kept with their endings)
     * between boundary delimiter lines. The chunk before the first delimiter
     * is the preamble (dropped); everything after the close delimiter is
     * epilogue (dropped). Returns null when no delimiter line exists at all.
     *
     * @return list<list<string>>|null
     */
    private static function splitSegments(string $chunk, string $boundary): ?array
    {
        $separator = '--' . $boundary;
        $lines = self::splitLinesKeepingEndings($chunk);
        $segments = [];
        $current = [];
        // Parsing mode, mirroring the Python engine's feedparser state
        // machine: 'preamble' before the first delimiter, 'consuming' right
        // after an inter-part boundary (the consume-consecutive-boundaries
        // loop swallows ANY delimiter lines that follow, INCLUDING a close
        // delimiter - the epilogue then parses as a part and the container
        // reports CloseBoundaryNotFoundDefect), and 'content' once a part
        // has lines.
        $mode = 'preamble';
        $inPart = false;
        $closed = false;
        foreach ($lines as $line) {
            $rest = str_starts_with($line, $separator) ? substr($line, strlen($separator)) : null;
            if ($rest !== null && preg_match('/^(--)?[ \t]*(?:\r\n|\r|\n)?$/', $rest, $m) === 1) {
                if ($mode === 'consuming') {
                    continue;
                }
                if (($m[1] ?? '') === '--') {
                    if ($mode === 'preamble') {
                        // Close delimiter before any part: everything stays
                        // preamble (StartBoundaryNotFoundDefect), so the
                        // caller falls back to the blob scan.
                        $closed = true;
                        break;
                    }
                    if ($current !== []) {
                        $segments[] = $current;
                        $current = [];
                    }
                    $closed = true;
                    break;
                }
                if ($mode === 'content' && $current !== []) {
                    $segments[] = $current;
                    $current = [];
                }
                $inPart = true;
                $mode = 'consuming';
                continue;
            }
            if ($mode === 'preamble') {
                continue;
            }
            $current[] = $line;
            $mode = 'content';
        }
        if (!$inPart) {
            // No inter-part boundary at all: the Python engine keeps the
            // chunk as a plain string payload and is_multipart() stays
            // False, so the caller falls back to the blob scan.
            return null;
        }
        if (!$closed && $current !== []) {
            // CloseBoundaryNotFoundDefect: parts parsed so far are kept.
            $segments[] = $current;
        }

        return $segments;
    }

    /**
     * Parse one part segment (its header block plus body) into leaf parts,
     * recursing into nested multipart containers. Adjacent delimiters
     * produce no part, so callers pass only non-empty line lists.
     *
     * @param list<string> $lines
     * @param list<array{?string, string, list<string>}> $parts
     */
    private static function collectSegmentParts(array $lines, int $binaryMinRunLength, array &$parts): void
    {
        [$headers, $body] = self::splitHeaders($lines);
        $contentType = '';
        foreach ($headers as [$name, $value]) {
            if (strtolower($name) === 'content-type') {
                $contentType = $value;
                break;
            }
        }
        $mediaType = self::mediaType($contentType);
        if ($mediaType !== null && str_starts_with($mediaType, 'multipart/')) {
            $boundary = self::boundaryOf($contentType);
            if ($boundary !== null) {
                $segments = self::splitSegments($body, $boundary);
                if ($segments !== null) {
                    foreach ($segments as $nested) {
                        self::collectSegmentParts($nested, $binaryMinRunLength, $parts);
                    }

                    return;
                }
                // StartBoundaryNotFoundDefect: the container payload stays a
                // plain string, so the container itself scans as a leaf with
                // the trailing newline kept (the parent's strip does not
                // apply to multipart children).
                $parts[] = self::partEntries($headers, $body, $contentType, false, $binaryMinRunLength);

                return;
            }
            // NoBoundaryInMultipartDefect: plain-string payload, no strip.
            $parts[] = self::partEntries($headers, $body, $contentType, false, $binaryMinRunLength);

            return;
        }
        // RFC 2046: the newline preceding the boundary belongs to the
        // boundary, so leaf payloads lose exactly one trailing line ending.
        $parts[] = self::partEntries($headers, $body, $contentType, true, $binaryMinRunLength);
    }

    /**
     * Header block then body, ported from the Python engine's _parsegen
     * collection loop plus _parse_headers with the exact input-position
     * semantics: a "From " line at the end of the collected header block is
     * pushed back into the input AFTER the consumed blank separator, so the
     * body starts at the From line with the separator blank gone; a non
     * header terminator line is pushed back and the body starts there; a
     * blank line just ends the block.
     *
     * @param list<string> $lines
     * @return array{list<array{string, string}>, string}
     */
    private static function splitHeaders(array $lines): array
    {
        // Phase 1: collection (headerRE lines until a blank or a pushed back
        // non header line).
        $headerLines = [];
        $terminator = null;
        $n = count($lines);
        $i = 0;
        for (; $i < $n; $i++) {
            $line = $lines[$i];
            if (self::isBareEnding($line)) {
                $i++;
                break;
            }
            if (!self::isHeaderLine($line)) {
                $terminator = $i;
                break;
            }
            $headerLines[] = $line;
        }
        $headerCount = count($headerLines);

        // Phase 2: header parsing (_parse_headers).
        $headers = [];
        $pendingName = null;
        $pendingValue = '';
        $fromPushback = false;
        foreach ($headerLines as $lineno => $line) {
            if ($line[0] === ' ' || $line[0] === "\t") {
                if ($pendingName === null) {
                    // FirstHeaderLineIsContinuationDefect: ignored.
                    continue;
                }
                $pendingValue .= $line;
                continue;
            }
            if ($pendingName !== null) {
                $headers[] = [$pendingName, self::finishHeaderValue($pendingValue)];
                $pendingName = null;
                $pendingValue = '';
            }
            if (str_starts_with($line, 'From ')) {
                if ($lineno === 0) {
                    continue;
                }
                if ($lineno === $headerCount - 1) {
                    $fromPushback = true;
                    break;
                }
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon === 0) {
                // InvalidHeaderDefect "Missing header name": dropped, the
                // pending header stays pending.
                continue;
            }
            $pendingName = $colon === false ? '' : substr($line, 0, $colon);
            $pendingValue = $colon === false ? '' : substr($line, $colon + 1);
        }
        if ($pendingName !== null) {
            $headers[] = [$pendingName, self::finishHeaderValue($pendingValue)];
        }

        // Body slice. Header lines occupy line indices 0..$headerCount-1.
        if ($fromPushback) {
            $bodyLines = array_merge(
                [$lines[$headerCount - 1]],
                array_slice($lines, $terminator !== null ? $headerCount : $headerCount + 1)
            );
        } elseif ($terminator !== null) {
            $bodyLines = array_slice($lines, $terminator);
        } else {
            $bodyLines = array_slice($lines, $i);
        }
        $body = implode('', $bodyLines);

        return [$headers, $body];
    }

    private static function isBareEnding(string $line): bool
    {
        return $line === "\r\n" || $line === "\n" || $line === "\r";
    }

    /**
     * The Python engine's headerRE: "From ", or a run of printable ASCII
     * excluding the colon followed by ':', or a continuation line starting
     * with a space or tab.
     */
    private static function isHeaderLine(string $line): bool
    {
        if ($line === '') {
            return false;
        }
        if (str_starts_with($line, 'From ')) {
            return true;
        }
        if ($line[0] === ' ' || $line[0] === "\t") {
            return true;
        }
        $colon = strpos($line, ':');
        // The name class excludes the colon, so the first colon terminates
        // the name; a zero-width name (': value') matches and is dropped as
        // an InvalidHeaderDefect during header parsing.
        if ($colon === false) {
            return false;
        }
        for ($i = 0; $i < $colon; $i++) {
            $o = ord($line[$i]);
            if ($o < 0x21 || $o === 0x3a || $o > 0x7e) {
                return false;
            }
        }

        return true;
    }

    private static function finishHeaderValue(string $value): string
    {
        return rtrim(ltrim($value, " \t\r\n"), "\r\n");
    }

    /**
     * The scanned values of one leaf part (Python _multipart_part_entries):
     * the sanitized filename entry, one entry per part header, then the
     * payload (binary-dense named file payloads reduced to binary islands).
     *
     * @param list<array{string, string}> $headers
     * @return array{?string, string, list<string>}
     */
    private static function partEntries(array $headers, string $payload, string $contentType, bool $stripEnding, int $binaryMinRunLength): array
    {
        if ($stripEnding) {
            $payload = preg_replace('/(?:\r\n|\r|\n)$/', '', $payload) ?? $payload;
        }
        $disposition = null;
        foreach ($headers as [$name, $value]) {
            if (strtolower($name) === 'content-disposition') {
                $disposition = $value;
                break;
            }
        }
        $nameParam = $disposition === null ? null : self::param($disposition, 'name');
        $name = $nameParam === null ? null : $nameParam[0];
        $filename = self::filename($disposition, $contentType);
        $exclusionKey = $name;
        $label = $exclusionKey ?? 'file';
        $values = [];
        if ($filename !== null) {
            $values[] = 'filename="' . str_replace(['"', "'"], '', $filename) . '"';
        }
        foreach ($headers as [$headerName, $headerValue]) {
            $values[] = $headerName . ': ' . $headerValue;
        }
        if ($filename !== null && BinaryIslands::valueIsBinaryLike($payload)) {
            foreach (BinaryIslands::extractBinaryIslands($payload, $binaryMinRunLength) as $island) {
                $values[] = $island;
            }
        } elseif ($payload !== '') {
            $values[] = $payload;
        }

        return [$exclusionKey, $label, $values];
    }

    /**
     * Split a urlencoded body the way Python parse_qsl(keep_blank_values)
     * does: fields separated by '&', each split at the first '=', both sides
     * form-unquoted ('+' becomes space, percent escapes decoded, invalid
     * bytes kept raw). Empty segments produce no pair.
     *
     * @return list<array{string, string}>
     */
    public static function parseQsl(string $rawBody): array
    {
        $pairs = [];
        foreach (explode('&', $rawBody) as $chunk) {
            if ($chunk === '') {
                continue;
            }
            $eq = strpos($chunk, '=');
            $name = $eq === false ? $chunk : substr($chunk, 0, $eq);
            $value = $eq === false ? '' : substr($chunk, $eq + 1);
            $pairs[] = [self::unquotePlus($name), self::unquotePlus($value)];
        }

        return $pairs;
    }

    private static function unquotePlus(string $s): string
    {
        return urldecode(str_replace('+', ' ', $s));
    }

    /**
     * The embedded JSON walk of one field or entry value: a value whose
     * JSON parses to an object or array walks leaf-first with the context
     * plus the :embedded_json suffix (keys scan as plain request_body
     * components, mongo-operator keys report straight from the walk); the
     * caller still scans the raw value afterwards, exactly like the
     * reference's embedded-JSON fall-through. Unparseable values produce no
     * walk entries.
     *
     * @param array<string, true> $excludedBodyFields
     * @return list<array{string, string, ?string}>
     */
    private static function embeddedJsonEntries(string $value, string $context, array $excludedBodyFields = []): array
    {
        $root = JsonWalk::parse($value);
        if ($root === null) {
            return [];
        }

        return JsonWalk::walkEntries($root, $context . JsonWalk::EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX, $excludedBodyFields);
    }

    /**
     * The boundary parameter of a multipart content type (Python
     * Message.get_boundary: the parameter with any trailing '=' padding
     * stripped), or null when the header does not carry one.
     */
    private static function boundaryOf(string $contentType): ?string
    {
        // Python get_boundary only accepts a plain string boundary; an RFC
        // 2231 extended boundary parameter is a tuple and counts as absent.
        $found = self::param($contentType, 'boundary');
        if ($found === null || $found[1] !== null) {
            return null;
        }

        return preg_replace('/=+$/', '', $found[0]) ?? $found[0];
    }

    /**
     * Lowercased "type/subtype" of a Content-Type-style value, or null when
     * the value is empty (the Python engine falls back to text/plain).
     */
    private static function mediaType(string $headerValue): ?string
    {
        $headerValue = trim($headerValue);
        if ($headerValue === '') {
            return null;
        }
        $type = $headerValue;
        $semi = self::splitParamsPosition($headerValue);
        if ($semi !== null) {
            $type = substr($headerValue, 0, $semi);
        }

        return strtolower(trim($type));
    }

    /**
     * First ';' that separates the media type from the parameters (outside
     * quoted strings; content type values never start with a quote, so a
     * plain scan is safe).
     */
    private static function splitParamsPosition(string $headerValue): ?int
    {
        $len = strlen($headerValue);
        for ($i = 0; $i < $len; $i++) {
            if ($headerValue[$i] === ';') {
                return $i;
            }
        }

        return null;
    }

    /**
     * A parameter from a Content-Type-style header in the shape the Python
     * engine's Message.get_param hands to the scanning surface:
     * [displayValue, tuple]. This is a faithful port of the reference
     * pipeline for parameters: _parseparam split, utils.unquote at
     * collection, utils.decode_params grouping of RFC 2231 continuations
     * (plain parameters always win over grouped ones regardless of
     * position, segments sort by number with a None number treated as 0
     * only when no zero exists, starred segments percent-decode as latin-1,
     * any starred segment makes the combined value extended, the combined
     * value is re-escaped with the RFC 2822 quoted-pair quote and split on
     * the charset/language ticks), and _unquotevalue.
     *
     * @return array{string, array{?string, ?string, string}|null}|null
     */
    private static function param(string $headerValue, string $paramName): ?array
    {
        $target = strtolower($paramName);
        $firstPlain = null;
        $groups = [];
        $groupOrder = [];
        foreach (self::headerParams($headerValue) as [$name, $value]) {
            if (preg_match('/^\\w+\\*(?:[0-9]+\\*?)?$/', $name) === 1) {
                $encoded = str_ends_with($name, '*');
                $num = null;
                if (preg_match('/^\\w+\\*([0-9]+)/', $name, $m) === 1) {
                    $num = (int) $m[1];
                }
                preg_match('/^(\\w+)\\*/', $name, $keyMatch);
                $groupKey = $keyMatch[1];
                if (!isset($groups[$groupKey])) {
                    $groups[$groupKey] = [];
                    $groupOrder[] = $groupKey;
                }
                $groups[$groupKey][] = [$num, $value, $encoded];
                continue;
            }
            if ($firstPlain === null && strtolower($name) === $target) {
                $firstPlain = [$value, null];
            }
        }
        if ($firstPlain !== null) {
            return $firstPlain;
        }
        foreach ($groupOrder as $groupKey) {
            if (strtolower($groupKey) !== $target) {
                continue;
            }
            return self::combineContinuations($groups[$groupKey]);
        }

        return null;
    }

    /**
     * utils.decode_params combining for one RFC 2231 continuation group.
     *
     * @param list<array{?int, string, bool}> $continuations [num, value, encoded]
     * @return array{string, array{?string, ?string, string}|null}
     */
    private static function combineContinuations(array $continuations): array
    {
        $hasZero = false;
        foreach ($continuations as [$num]) {
            if ($num === 0) {
                $hasZero = true;
                break;
            }
        }
        $kept = [];
        foreach ($continuations as [$num, $value, $encoded]) {
            if ($hasZero && $num === null) {
                continue;
            }
            $kept[] = [$num ?? 0, $value, $encoded];
        }
        usort($kept, static fn (array $a, array $b): int => $a[0] <=> $b[0]);
        $parts = [];
        $extended = false;
        foreach ($kept as [, $value, $encoded]) {
            if ($encoded) {
                $parts[] = rawurldecode($value);
                $extended = true;
            } else {
                $parts[] = $value;
            }
        }
        $joined = self::quoteRfc2822(implode('', $parts));
        if (!$extended) {
            return [self::unquoteParam('"' . $joined . '"'), null];
        }
        $split = explode("'", $joined, 3);
        if (count($split) < 3) {
            $charset = null;
            $language = null;
            $text = $joined;
        } else {
            [$charset, $language, $text] = $split;
        }
        $unquotedText = self::unquoteParam('"' . $text . '"');

        return [
            self::tupleStr([$charset, $language, $unquotedText]),
            [$charset, $language, $unquotedText],
        ];
    }

    /**
     * The filename of a part (Python Message.get_filename): the
     * content-disposition filename parameter, falling back to the
     * content-type name parameter, collapsed from any RFC 2231 tuple and
     * whitespace-stripped.
     */
    private static function filename(?string $disposition, string $contentType): ?string
    {
        $found = ($disposition !== null ? self::param($disposition, 'filename') : null)
            ?? self::param($contentType, 'name');
        if ($found === null) {
            return null;
        }
        [$value, $tuple] = $found;
        if ($tuple === null) {
            return trim($value);
        }
        [$charset, , $text] = $tuple;
        if ($charset === null || $charset === '') {
            // None charset falls back to us-ascii with errors='replace'.
            return trim(self::usAsciiReplace($text));
        }
        $converted = @mb_convert_encoding($text, 'UTF-8', strtolower($charset));
        if (is_string($converted)) {
            return trim($converted);
        }
        // Unknown charset: the Python engine catches LookupError and
        // returns the already-unquoted text.
        return trim($text);
    }

    /**
     * Python str(rawbytes, 'us-ascii', errors='replace').
     */
    private static function usAsciiReplace(string $bytes): string
    {
        $out = '';
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            $out .= ord($bytes[$i]) >= 0x80 ? "\u{FFFD}" : $bytes[$i];
        }

        return $out;
    }

    /**
     * email._parseaddr.quote: quoted-pair escaping of backslash and double
     * quote, without the surrounding quotes.
     */
    private static function quoteRfc2822(string $s): string
    {
        // Python order: backslashes first, then quotes.
        return str_replace('"', '\\"', str_replace('\\', '\\\\', $s));
    }

    /**
     * str() of a Python (charset, language, text) tuple: repr() of each
     * element, comma-space separated inside parentheses.
     *
     * @param array{?string, ?string, string} $tuple
     */
    private static function tupleStr(array $tuple): string
    {
        return '(' . implode(', ', array_map(static fn (?string $el): string => $el === null ? 'None' : self::pyRepr($el), $tuple)) . ')';
    }

    private static function pyRepr(string $s): string
    {
        if (str_contains($s, "'") && !str_contains($s, '"')) {
            return '"' . addcslashes($s, '"\\') . '"';
        }

        return "'" . addcslashes($s, "'\\") . "'";
    }

    /**
     * Split a header value into [rawName, unquotedValue] pairs. Semicolons
     * inside quoted strings do not split; quoted values lose their quotes
     * and backslash escapes; '=' padding on boundary tokens is kept (the
     * Python engine rstrips it only for boundaries).
     *
     * @return list<array{string, string}>
     */
    private static function headerParams(string $headerValue): array
    {
        $params = [];
        $len = strlen($headerValue);
        $start = null;
        $inQuotes = false;
        $escaped = false;
        for ($i = 0; $i < $len; $i++) {
            $ch = $headerValue[$i];
            if ($escaped) {
                $escaped = false;
                continue;
            }
            if ($inQuotes) {
                if ($ch === '\\') {
                    $escaped = true;
                } elseif ($ch === '"') {
                    $inQuotes = false;
                }
                continue;
            }
            if ($ch === '"') {
                $inQuotes = true;
                continue;
            }
            if ($ch === ';') {
                $params[] = substr($headerValue, $start ?? 0, $i - ($start ?? 0));
                $start = $i + 1;
            }
        }
        if ($start !== null) {
            $params[] = substr($headerValue, $start);
        }
        $out = [];
        foreach ($params as $raw) {
            $eq = strpos($raw, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($raw, 0, $eq));
            $value = self::unquoteParam(trim(substr($raw, $eq + 1)));
            $out[] = [$key, $value];
        }

        return $out;
    }

    /**
     * Strip one pair of surrounding quotes and process backslash escapes
     * (Python _unquotevalue / unquote).
     */
    private static function unquoteParam(string $value): string
    {
        if (strlen($value) >= 2 && str_starts_with($value, '"') && str_ends_with($value, '"')) {
            $value = substr($value, 1, -1);
            // Python utils.unquote: only the quoted-pair escapes \\\\ and
            // \\" are processed, in that order.
            $value = str_replace('\\\\', "\x00", $value);
            $value = str_replace('\\"', '"', $value);
            $value = str_replace("\x00", '\\', $value);
        }

        return $value;
    }

    /**
     * Split into lines keeping their line endings (\r\n, \n, or \r), the
     * way the Python engine's incremental feedparser reads lines.
     *
     * @return list<string>
     */
    private static function splitLinesKeepingEndings(string $s): array
    {
        if ($s === '') {
            return [];
        }
        $pieces = preg_split('/(\r\n|\r|\n)/', $s, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [$s];
        $lines = [];
        $count = count($pieces);
        for ($i = 0; $i < $count; $i += 2) {
            $line = $pieces[$i];
            $ending = $pieces[$i + 1] ?? '';
            if ($line === '' && $ending === '' && $i === $count - 1) {
                // Trailing artifact of the split after a final line ending.
                break;
            }
            $lines[] = $line . $ending;
        }

        return $lines;
    }
}
