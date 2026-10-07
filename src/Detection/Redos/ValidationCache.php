<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection\Redos;

/**
 * The disk-backed cache for the pattern-safety validator's expensive
 * layer, ported from the reference _validation_cache.py: the cheap
 * deterministic layers (dangerous constructs, compile check, structural
 * detectors) always re-run; only the empirical cost-verdict outcome is
 * cached, keyed by pattern, flags and engine version, so a boot on a
 * degraded host reuses prior certifications instead of re-timing every
 * custom pattern, and a pattern table never silently reuses a verdict
 * produced by a different engine version.
 *
 * File shape: a JSON object mapping sha256(pattern 0x00 flags) hex keys to
 * {version, safe, reason} entries; entries from a different engine version
 * are dropped on load, a corrupt file starts empty with a warning, and a
 * write is atomic (tmp file plus rename).
 */
final class ValidationCache
{
    /**
     * The cache-invalidating engine identity (the reference's installed
     * package version): bumped with every release so verdicts from an
     * older engine never load.
     */
    public const ENGINE_VERSION = '4.3.1';

    /** @var array<string, array{version: string, safe: bool, reason: string}> */
    private array $entries = [];

    public function __construct(private readonly string $path)
    {
        $this->load();
    }

    /**
     * Reference _key: sha256 over pattern, a 0x00 separator and the flags.
     */
    public static function key(string $pattern, bool $ignoreCase): string
    {
        return hash('sha256', $pattern . "\x00" . ($ignoreCase ? 'i' : ''));
    }

    /** @return array{safe: bool, reason: string}|null the cached verdict */
    public function get(string $pattern, bool $ignoreCase): ?array
    {
        $entry = $this->entries[self::key($pattern, $ignoreCase)] ?? null;
        if ($entry === null) {
            return null;
        }

        return ['safe' => $entry['safe'], 'reason' => $entry['reason']];
    }

    public function put(string $pattern, bool $ignoreCase, bool $safe, string $reason): void
    {
        $this->entries[self::key($pattern, $ignoreCase)] = [
            'version' => self::ENGINE_VERSION,
            'safe' => $safe,
            'reason' => $reason,
        ];
        $this->persist();
    }

    private function load(): void
    {
        $raw = @file_get_contents($this->path);
        if ($raw === false) {
            return;
        }
        try {
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($data)) {
                throw new \JsonException('cache root is not an object');
            }
            $entries = [];
            foreach ($data as $key => $entry) {
                if (!is_array($entry)) {
                    throw new \JsonException('cache entry is not an object');
                }
                if (($entry['version'] ?? null) !== self::ENGINE_VERSION) {
                    continue;
                }
                if (!is_bool($entry['safe'] ?? null) || !is_string($entry['reason'] ?? null)) {
                    throw new \JsonException('cache entry missing a verdict');
                }
                $entries[(string) $key] = [
                    'version' => self::ENGINE_VERSION,
                    'safe' => $entry['safe'],
                    'reason' => $entry['reason'],
                ];
            }
            $this->entries = $entries;
        } catch (\JsonException $e) {
            error_log('[guard_core] Pattern validation cache corrupt, starting empty: ' . $e->getMessage());
        }
    }

    private function persist(): void
    {
        $tmpPath = $this->path . '.tmp';
        try {
            $payload = json_encode($this->entries, JSON_THROW_ON_ERROR);
            if (@file_put_contents($tmpPath, $payload) === false || !@rename($tmpPath, $this->path)) {
                @unlink($tmpPath);
                throw new \RuntimeException('atomic write failed');
            }
        } catch (\Throwable $e) {
            error_log('[guard_core] Pattern validation cache write failed: ' . $e->getMessage());
        }
    }
}
