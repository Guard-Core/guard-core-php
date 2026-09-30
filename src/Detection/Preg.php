<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Support\Text;

final class Preg
{
    public static function compile(string $source, bool $ignoreCase = true): string
    {
        $translated = str_replace('\\Z', '\\z', $source);
        $delim = str_contains($translated, "\x01") ? "\x02" : "\x01";
        $translated = '(*UCP)' . $translated;

        return $delim . $translated . $delim . 'u' . ($ignoreCase ? 'i' : '');
    }

    public static function safeEval(string $pattern, string $subject): ?array
    {
        $m = [];
        $ok = @preg_match($pattern, $subject, $m, PREG_OFFSET_CAPTURE);
        if ($ok === false) {
            throw new PregFailure(preg_last_error_msg(), preg_last_error());
        }
        if ($ok === 0) {
            return null;
        }

        return self::groupsFrom($m);
    }

    public static function groupsFrom(array $m): array
    {
        $groups = [];
        foreach ($m as $gi => $g) {
            if (!is_array($g) || !isset($g[0]) || $g[1] < 0) {
                $groups[$gi] = null;
                continue;
            }
            $groups[$gi] = ['text' => $g[0], 'start' => $g[1], 'end' => $g[1] + strlen($g[0])];
        }

        return $groups;
    }

    public static function allMatches(string $source, string $subject, bool $ignoreCase = true): array
    {
        return self::allMatchesFrom(self::compile($source, $ignoreCase), $subject);
    }

    public static function allMatchesFrom(string $pattern, string $subject): array
    {
        $m = [];
        $ok = @preg_match_all($pattern, $subject, $m, PREG_OFFSET_CAPTURE);
        if ($ok === false) {
            throw new PregFailure(preg_last_error_msg(), preg_last_error());
        }
        if ($ok === 0) {
            return [];
        }
        $out = [];
        foreach ($m[0] as $i => $hit) {
            $groups = [];
            foreach ($m as $gi => $group) {
                if ($gi === 0) {
                    continue;
                }
                $g = $group[$i] ?? null;
                if ($g === null || !is_array($g) || $g[1] < 0) {
                    $groups[$gi] = null;
                } else {
                    $groups[$gi] = ['text' => $g[0], 'start' => $g[1], 'end' => $g[1] + strlen($g[0])];
                }
            }
            $out[] = [
                'start' => $hit[1],
                'end' => $hit[1] + strlen($hit[0]),
                'text' => $hit[0],
                'groups' => $groups,
            ];
        }

        return $out;
    }

    public static function matchAnchoredAt(string $source, string $subject, int $byteStart, ?int $byteEnd = null, bool $ignoreCase = true): ?array
    {
        $segment = $byteEnd === null
            ? substr($subject, $byteStart)
            : substr($subject, $byteStart, $byteEnd - $byteStart);
        if ($segment === false || $segment === '') {
            return null;
        }
        $anchored = self::compile('\A(?:' . $source . ')', $ignoreCase);
        $m = [];
        $ok = @preg_match($anchored, $segment, $m, PREG_OFFSET_CAPTURE);
        if ($ok === false) {
            throw new PregFailure(preg_last_error_msg(), preg_last_error());
        }
        if ($ok !== 1) {
            return null;
        }
        $rel = $m[0][1];
        $groups = [];
        foreach ($m as $gi => $g) {
            if ($gi === 0) {
                continue;
            }
            if (!is_array($g) || $g[1] < 0) {
                $groups[$gi] = null;
            } else {
                $groups[$gi] = ['text' => $g[0], 'start' => $byteStart + $g[1], 'end' => $byteStart + $g[1] + strlen($g[0])];
            }
        }

        return [
            'start' => $byteStart + $rel,
            'end' => $byteStart + $rel + strlen($m[0][0]),
            'text' => $m[0][0],
            'groups' => $groups,
        ];
    }

    public static function searchFrom(string $source, string $subject, int $byteOffset, bool $ignoreCase = true): ?array
    {
        $segment = $byteOffset > 0 ? substr($subject, $byteOffset) : $subject;
        if ($segment === '') {
            return null;
        }
        $m = [];
        $ok = @preg_match(self::compile($source, $ignoreCase), $segment, $m, PREG_OFFSET_CAPTURE);
        if ($ok === false) {
            throw new PregFailure(preg_last_error_msg(), preg_last_error());
        }
        if ($ok !== 1) {
            return null;
        }

        return [
            'start' => $byteOffset + $m[0][1],
            'end' => $byteOffset + $m[0][1] + strlen($m[0][0]),
            'text' => $m[0][0],
            'groups' => self::groupsFrom($m),
        ];
    }

    public static function searchOne(string $source, string $subject, bool $ignoreCase = true): ?array
    {
        $m = self::allMatches($source, $subject, $ignoreCase);

        return $m[0] ?? null;
    }

    public static function hasMatch(string $source, string $subject, bool $ignoreCase = true): bool
    {
        return self::searchOne($source, $subject, $ignoreCase) !== null;
    }

    public static function replace(string $source, string $subject, callable $fn, bool $ignoreCase = true): string
    {
        $count = 0;

        return @preg_replace_callback(
            self::compile($source, $ignoreCase),
            static function (array $m) use ($fn): string {
                $groups = [];
                foreach ($m as $gi => $g) {
                    if ($gi === 0) {
                        continue;
                    }
                    $groups[$gi] = is_array($g)
                        ? ['text' => $g[0], 'start' => $g[1], 'end' => $g[1] + strlen($g[0])]
                        : null;
                }

                return $fn(['text' => $m[0][0], 'start' => $m[0][1], 'end' => $m[0][1] + strlen($m[0][0]), 'groups' => $groups]);
            },
            $subject,
            -1,
            $count,
            PREG_OFFSET_CAPTURE
        ) ?? $subject;
    }

    public static function cp(string $subject, int $byteOffset): int
    {
        return Text::bytesToCp($subject, $byteOffset);
    }
}

final class PregFailure extends \RuntimeException
{
    /**
     * preg_last_error() captured at throw time. The ScanGuard classifies
     * backtrack/recursion trips as scan timeouts; reading the code here
     * rather than from the process-global state avoids misclassifying a
     * synthetic failure after an unrelated preg call left a stale code.
     */
    public readonly int $pregErrorCode;

    public function __construct(string $message, int $pregErrorCode = PREG_NO_ERROR)
    {
        parent::__construct($message);
        $this->pregErrorCode = $pregErrorCode;
    }
}
