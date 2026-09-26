<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Behavior;

/**
 * The shared per-IP per-category suspicious-count store. Owned by the
 * engine so the behavioral processor's correlate_with_detection reads the
 * same counts the suspicious_activity check writes, mirroring the reference
 * reading middleware.suspicious_request_counts
 * (guard_core/core/behavioral/processor.py _collect_correlated_categories).
 */
final class SuspiciousCountStore
{
    /** @var array<string, array<string, int>> */
    private array $counts = [];

    public function record(string $ip, string $category): void
    {
        $this->counts[$ip][$category] = ($this->counts[$ip][$category] ?? 0) + 1;
    }

    /**
     * Mirrors _collect_correlated_categories: the detection categories with
     * a positive suspicious count for the IP, sorted.
     *
     * @return list<string>
     */
    public function correlatedCategories(string $ip): array
    {
        $categories = [];
        foreach ($this->counts[$ip] ?? [] as $category => $count) {
            if ($count > 0) {
                $categories[] = $category;
            }
        }
        sort($categories);

        return $categories;
    }
}
