<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;
use RenzoFranceschini\GuardCore\Support\Generated\HtmlEntities;
use RenzoFranceschini\GuardCore\Support\Unicode;

final class Preprocessor
{
    public const MAX_FULL_SCAN_BYTES = 262144;
    public const FULL_SCAN_TAIL_BYTES = 4096;
    public const MAX_DECODE_ITERATIONS = 16;

    public const ATTACK_INDICATORS = [
        '<script',
        'javascript:',
        'on\w+=',
        'SELECT\s+.{0,50}?\s+FROM',
        'UNION\s+SELECT',
        '\.\./',
        'eval\s*\(',
        'exec\s*\(',
        'system\s*\(',
        '<\?php',
        '<%',
        '{{',
        '{%',
        '<iframe',
        '<object',
        '<embed',
        'onerror\s*=',
        'onload\s*=',
        '\$\{',
        '\\\\x[0-9a-fA-F]{2}',
        '%[0-9a-fA-F]{2}',
        '`',
        '\$\(',
        '[;&|]',
        '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    ];

    public function normalizeUnicode(string $content): string
    {
        return Unicode::normalize($content);
    }

    public function removeExcessiveWhitespace(string $content): string
    {
        $collapsed = preg_replace(self::wsRe(), ' ', $content) ?? $content;

        return $this->pyTrim($collapsed);
    }

    private static function wsRe(): string
    {
        return '/(?:[\x09-\x0d\x20\x1c-\x1f]|\x{0085}|[\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}])+/u';
    }

    private function pyTrim(string $s): string
    {
        $n = Text::len($s);
        $start = 0;
        while ($start < $n) {
            $ch = Text::slice($s, $start, 1);
            if (!preg_match(self::wsRe(), $ch)) {
                break;
            }
            $start++;
        }
        $end = $n;
        while ($end > $start) {
            $ch = Text::slice($s, $end - 1, 1);
            if (!preg_match(self::wsRe(), $ch)) {
                break;
            }
            $end--;
        }

        return Text::slice($s, $start, $end - $start);
    }

    public function removeNullBytes(string $content): string
    {
        $out = '';
        $len = strlen($content);
        for ($i = 0; $i < $len; $i++) {
            $byte = $content[$i];
            if ($byte === "\x00") {
                continue;
            }
            if ($byte < "\x20" && $byte !== "\x09" && $byte !== "\x0a" && $byte !== "\x0d") {
                continue;
            }
            $out .= $byte;
        }

        return $out;
    }

    public function decodeOverlongUtf8PercentRuns(string $content): string
    {
        return Preg::replace('(?:%[0-9a-fA-F]{2})+', $content, static function (array $m): string {
            $run = $m['text'];
            $raw = '';
            for ($i = 0, $n = strlen($run); $i < $n; $i += 3) {
                $raw .= chr((int) hexdec(substr($run, $i + 1, 2)));
            }
            if (mb_check_encoding($raw, 'UTF-8')) {
                return $run;
            }

            return self::lenientOverlongUtf8Decode($raw);
        });
    }

    private const OVERLONG_LEAD_SPECS = [
        0xc0 => [2, 0x1f, 0x80, 0xbf],
        0xc1 => [2, 0x1f, 0x80, 0xbf],
        0xe0 => [3, 0x0f, 0x80, 0x9f],
        0xf0 => [4, 0x07, 0x80, 0x8f],
    ];

    public static function lenientOverlongUtf8Decode(string $raw): string
    {
        $out = '';
        $len = strlen($raw);
        $i = 0;
        while ($i < $len) {
            $byte = ord($raw[$i]);
            $spec = self::OVERLONG_LEAD_SPECS[$byte] ?? null;
            $decoded = null;
            if ($spec !== null && $i + $spec[0] <= $len) {
                [$seqLen, $leadMask, $contMin, $contMax] = $spec;
                $first = ord($raw[$i + 1]);
                if ($first >= $contMin && $first <= $contMax) {
                    $ok = true;
                    $cp = $byte & $leadMask;
                    for ($j = 2; $j < $seqLen; $j++) {
                        $b = ord($raw[$i + $j]);
                        if ($b < 0x80 || $b > 0xbf) {
                            $ok = false;
                            break;
                        }
                        $cp = ($cp << 6) | ($b & 0x3f);
                    }
                    if ($ok) {
                        $decoded = [$cp, $seqLen];
                    }
                }
            }
            if ($decoded !== null) {
                $out .= Text::chr($decoded[0]);
                $i += $decoded[1];
            } elseif ($byte < 0x80) {
                $out .= chr($byte);
                $i++;
            } else {
                $i++;
            }
        }

        return $out;
    }

    public function urlDecode(string $content): string
    {
        $bytes = '';
        $len = strlen($content);
        $i = 0;
        while ($i < $len) {
            $c = $content[$i];
            if ($c === '%' && $i + 2 < $len && ctype_xdigit(substr($content, $i + 1, 2))) {
                $bytes .= chr((int) hexdec(substr($content, $i + 1, 2)));
                $i += 3;
            } else {
                $cp = ord($c);
                if ($cp < 0x80) {
                    $bytes .= $c;
                    $i++;
                    continue;
                }
                $n = $cp < 0xe0 ? 2 : ($cp < 0xf0 ? 3 : 4);
                $seq = substr($content, $i, $n);
                if (mb_check_encoding($seq, 'UTF-8') && strlen($seq) === $n) {
                    $bytes .= $seq;
                }
                $i++;
            }
        }

        return self::utf8DecodeIgnoring($bytes);
    }

    private static function utf8DecodeIgnoring(string $bytes): string
    {
        $out = '';
        $len = strlen($bytes);
        $i = 0;
        while ($i < $len) {
            $cp = ord($bytes[$i]);
            if ($cp < 0x80) {
                $out .= $bytes[$i];
                $i++;
                continue;
            }
            $n = $cp < 0xc0 ? 1 : ($cp < 0xe0 ? 2 : ($cp < 0xf0 ? 3 : 4));
            $seq = $n === 1 ? '' : substr($bytes, $i, $n);
            if ($n > 1 && strlen($seq) === $n && mb_check_encoding($seq, 'UTF-8')) {
                $out .= $seq;
                $i += $n;
                continue;
            }
            $i++;
        }

        return $out;
    }

    public function htmlUnescape(string $content): string
    {
        return Preg::replace(
            '&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)',
            $content,
            static fn (array $m): string => self::replaceCharRef($m['text'])
        );
    }

    private static function replaceCharRef(string $ref): string
    {
        $body = substr($ref, 1);
        if ($body !== '' && $body[0] === '#') {
            $isHex = strlen($body) > 1 && ($body[1] === 'x' || $body[1] === 'X');
            $digits = $isHex ? substr($body, 2) : substr($body, 1);
            $hadSemicolon = str_ends_with($digits, ';');
            if ($hadSemicolon) {
                $digits = substr($digits, 0, -1);
            }
            if ($digits === '') {
                return $ref;
            }
            $num = $isHex ? hexdec($digits) : (int) $digits;
            if ($num > 0x10ffff || ($num >= 0xd800 && $num <= 0xdfff) || $num === 0) {
                return "\u{FFFD}";
            }

            return Text::chr($num);
        }
        if (isset(HtmlEntities::HTML5[$body])) {
            return HtmlEntities::HTML5[$body];
        }
        $len = strlen($body);
        for ($x = $len - 1; $x >= 2; $x--) {
            $prefix = substr($body, 0, $x);
            if (isset(HtmlEntities::HTML5[$prefix])) {
                return HtmlEntities::HTML5[$prefix] . substr($body, $x);
            }
        }

        return $ref;
    }

    public function decodePercentUEscapes(string $content): string
    {
        return Preg::replace('%u([0-9a-fA-F]{4})', $content, static fn (array $m): string => Text::chr((int) hexdec($m['groups'][1]['text'])));
    }

    public function decodeHexEscapes(string $content): string
    {
        return Preg::replace('\\\\x([0-9a-fA-F]{2})', $content, static fn (array $m): string => Text::chr((int) hexdec($m['groups'][1]['text'])));
    }

    public function decodeUnicodeEscapes(string $content): string
    {
        return Preg::replace('\\\\u([0-9a-fA-F]{4})', $content, static fn (array $m): string => Text::chr((int) hexdec($m['groups'][1]['text'])));
    }

    public function decodeLdapHexEscapes(string $content): string
    {
        return Preg::replace('\\\\([0-9a-fA-F]{2})', $content, static fn (array $m): string => Text::chr((int) hexdec($m['groups'][1]['text'])));
    }

    public function decodeBase64Candidates(string $content, array &$gunzipLeft): string
    {
        return Base64::decodeCandidates($content, $gunzipLeft, self::MAX_FULL_SCAN_BYTES);
    }

    public function stripSqlComments(string $content): string
    {
        $blockRe = '/(?<!\w)\/\*(?!!)(.*?)\*\/|\/\*(?!!)(.*?)\*\/(?!\w)/s';
        $content = preg_replace_callback(
            $blockRe,
            static function (array $m): string {
                $body = $m[1] !== null && $m[1] !== '' ? $m[1] : $m[2];

                return ' ' . $body . ' ';
            },
            $content
        ) ?? $content;

        return str_replace(['--', '#'], ' ', $content);
    }

    public function decodeCommonEncodings(string $content, array &$decodeBudgetExhausted): string
    {
        $iterations = 0;
        $gunzipLeft = [Base64::MAX_GUNZIP_ATTEMPTS_PER_PASS];
        while ($iterations < self::MAX_DECODE_ITERATIONS) {
            $original = $content;
            $content = $this->decodeOverlongUtf8PercentRuns($content);
            $decoded = $this->urlDecode($content);
            if ($decoded !== $content) {
                $content = $decoded;
            }
            $decoded = $this->htmlUnescape($content);
            if ($decoded !== $content) {
                $content = $decoded;
            }
            $content = $this->decodePercentUEscapes($content);
            $content = $this->decodeHexEscapes($content);
            $content = $this->decodeLdapHexEscapes($content);
            $content = $this->decodeUnicodeEscapes($content);
            $content = $this->normalizeUnicode($content);
            $content = $this->decodeBase64Candidates($content, $gunzipLeft);
            if ($content === $original) {
                break;
            }
            $iterations++;
        }
        if ($iterations >= self::MAX_DECODE_ITERATIONS && $content !== $original) {
            // The budget flag rides the by-ref array the callers pass in
            // ([false]); writing a bare bool clobbers the array and the
            // callers' [0] read silently turns into null.
            $decodeBudgetExhausted[0] = true;
        }
        $content = $this->stripSqlComments($content);

        return $content;
    }

    public function preprocessWithDecoded(string $content, array &$decodeBudgetExhausted): array
    {
        if ($content === '') {
            return ['', ''];
        }
        $decoded = $this->normalizeUnicode($content);
        $decoded = $this->decodeCommonEncodings($decoded, $decodeBudgetExhausted);
        $processed = $this->removeNullBytes($decoded);
        $processed = $this->removeExcessiveWhitespace($processed);
        $processed = Truncation::truncateSafely($processed, $this);

        return [$processed, $decoded];
    }

    public function preprocessSignalPreserving(string $content): string
    {
        if ($content === '') {
            return '';
        }
        $content = $this->normalizeUnicode($content);

        return Truncation::truncateSafely($content, $this);
    }

    public function preprocessUrlDecodedNewlinePreserving(string $content, array &$decodeBudgetExhausted): string
    {
        if ($content === '') {
            return '';
        }
        $content = $this->normalizeUnicode($content);
        $content = $this->decodeCommonEncodings($content, $decodeBudgetExhausted);

        return Truncation::truncateSafely($content, $this);
    }

    public function preprocessShortBase64AdditiveView(string $content): string
    {
        if ($content === '') {
            return '';
        }
        $content = $this->normalizeUnicode($content);
        $content = Truncation::truncateSafely($content, $this);
        $fragments = [];
        $attempts = 0;
        foreach (Preg::allMatches('[A-Za-z0-9+/]{4,}', $content) as $m) {
            if ($attempts >= 20000) {
                break;
            }
            $attempts++;
            $decoded = Base64::decodeShortToken($m['text']);
            if ($decoded === null || Base64::printableRatio($decoded) < 0.95) {
                continue;
            }
            if (!str_contains($decoded, '$') && !str_contains($decoded, '{') && !str_contains($decoded, '}') && !str_contains($decoded, '#')) {
                continue;
            }
            $fragments[] = $decoded;
        }

        return implode("\n", $fragments);
    }
}
