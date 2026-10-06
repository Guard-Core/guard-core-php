<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Logging;

/**
 * setup_custom_logging parity (logging_utils.py): builds the engine-facing
 * logger from the log_format / log_file knobs. The text layout mirrors
 * "[%(name)s] %(asctime)s - %(levelname)s - %(message)s"; the json layout
 * is the JsonFormatter record. Both write one line per record to the
 * console (error_log) and, when a log file is configured, append the same
 * line to the file (the directory is created on demand; a failed file
 * setup logs a warning and stays console-only, like the reference).
 *
 * Level handling mirrors logger.setLevel(logging.INFO): DEBUG records are
 * dropped. Context arrays are intentionally NOT rendered (the reference
 * formatter formats the message only).
 *
 * Divergences (documented): python-logging's handler lifecycle has no PHP
 * counterpart - there is no global logger registry to re-configure, so the
 * "remove previously installed own handlers" step is inapplicable-idiom
 * (each call returns a fresh independent logger), and the
 * _YieldToHostRootHandlers filter (console emission suppressed when the
 * host application owns the root logger) becomes the explicit
 * $hostOwnsLogging flag.
 */
final class LogSetup
{
    public const DEFAULT_CHANNEL = 'guard_core';

    public const FORMAT_TEXT = 'text';

    public const FORMAT_JSON = 'json';

    public static function setupCustomLogging(
        ?string $logFile = null,
        string $logFormat = self::FORMAT_TEXT,
        bool $hostOwnsLogging = false,
        string $channel = self::DEFAULT_CHANNEL
    ): RequestLogger {
        if ($logFormat !== self::FORMAT_TEXT && $logFormat !== self::FORMAT_JSON) {
            throw new \InvalidArgumentException("log_format: unknown format '{$logFormat}'");
        }
        $fileReady = self::prepareLogFile($logFile);
        $formatter = new JsonFormatter();

        return new class($logFile, $logFormat, $fileReady, $hostOwnsLogging, $formatter, self::DEFAULT_CHANNEL) implements RequestLogger {
            public function __construct(
                private readonly ?string $logFile,
                private readonly string $logFormat,
                private readonly bool $fileReady,
                private readonly bool $hostOwnsLogging,
                private readonly JsonFormatter $formatter,
                private readonly string $channel
            ) {
            }

            /** @param array<string, mixed> $context */
            public function log(string $level, string $message, array $context = []): void
            {
                if (strtolower($level) === 'debug') {
                    return;
                }
                $line = $this->logFormat === LogSetup::FORMAT_JSON
                    ? $this->formatter->format($level, $this->channel, $message)
                    : sprintf(
                        '[%s] %s - %s - %s',
                        $this->channel,
                        (new \DateTimeImmutable())->format('Y-m-d H:i:s.v'),
                        strtoupper($level),
                        $message
                    );
                if (!$this->hostOwnsLogging) {
                    LogSetup::emitConsole($line);
                }
                if ($this->fileReady && $this->logFile !== null) {
                    @file_put_contents($this->logFile, $line . "\n", FILE_APPEND | LOCK_EX);
                }
            }
        };
    }

    /**
     * The engine's default-log-closure factory: adapters hand
     * LogSetup::setupCustomLogging(...)->log(...) to GuardEngine when they
     * want the structured surface; the config switch (log_format) makes
     * the JSON shape available without any custom closure.
     */
    public static function engineLogClosure(\RenzoFranceschini\GuardCore\Config\SecurityConfig $config): \Closure
    {
        $logger = self::setupCustomLogging(logFormat: $config->logFormat);

        return static function (string $level, string $message, array $context = []) use ($logger): void {
            $logger->log($level, $message, $context);
        };
    }

    private static function prepareLogFile(?string $logFile): bool
    {
        if ($logFile === null || $logFile === '') {
            return false;
        }
        try {
            $dir = dirname($logFile);
            if ($dir !== '' && $dir !== '.' && !is_dir($dir)) {
                if (!@mkdir($dir, 0777, true) && !is_dir($dir)) {
                    throw new \RuntimeException("unable to create directory {$dir}");
                }
            }

            return true;
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to create log file ' . $logFile . ': ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Console emission writes bare lines to stderr (the python
     * StreamHandler shape); error_log is the fallback. error_log alone
     * would be wrong here: with the error_log ini pointed at a file, PHP
     * prepends a "[date timezone]" header to every line, which corrupts
     * the structured records.
     */
    public static function emitConsole(string $line): void
    {
        if (@file_put_contents('php://stderr', $line . "\n") === false) {
            error_log($line);
        }
    }
}
