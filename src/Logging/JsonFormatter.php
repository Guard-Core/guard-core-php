<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

/**
 * The JSON structured-log formatter, ported from the reference
 * logging_utils.py JsonFormatter: exactly four fields, in this key order -
 * timestamp (the python asctime shape "Y-m-d H:i:s,v"), level (uppercase
 * record level), logger (channel name), message.
 *
 * Divergence (documented): python's json.dumps default escapes every
 * non-ASCII byte to \uXXXX and never fails; PHP's json_encode returns
 * false on malformed UTF-8, so the formatter substitutes invalid
 * sequences (JSON_INVALID_UTF8_SUBSTITUTE) instead of dropping the line.
 */
final class JsonFormatter
{
    public function format(string $level, string $logger, string $message, ?\DateTimeImmutable $at = null): string
    {
        $timestamp = ($at ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->setTimezone(new \DateTimeZone(date_default_timezone_get()))
            ->format('Y-m-d H:i:s.v');
        $line = json_encode(
            [
                'timestamp' => $timestamp,
                'level' => strtoupper($level),
                'logger' => $logger,
                'message' => $message,
            ],
            JSON_INVALID_UTF8_SUBSTITUTE
        );

        // json_encode over an array of strings with the substitute flag
        // cannot fail; the fallback keeps the log path total.
        return $line === false ? '{"timestamp":"","level":"","logger":"","message":""}' : $line;
    }
}
