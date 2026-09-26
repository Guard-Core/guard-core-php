<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\GeoIp;

/**
 * The built-in CountryResolver: a lazily opened MMDB reader over a locally
 * provisioned database file, standing in for the reference IPInfoManager
 * minus the download lifecycle (the port reads a local database instead of
 * fetching country_asn.mmdb with an IPInfo token; the download/refresh and
 * Redis-cache lifecycle stays deferred, matching guard-core-go #23).
 *
 * A missing or corrupted database is a soft failure: every lookup reports
 * a miss, exactly like the reference reader returning None after a failed
 * initialization. A corrupted database is removed, mirroring the reference
 * _open_database_or_none, so a refreshed copy can take its place.
 */
final class GeoIpManager implements CountryResolver
{
    private ?MmdbReader $reader = null;

    private bool $failed = false;

    public function __construct(private readonly string $dbPath)
    {
    }

    public function dbPath(): string
    {
        return $this->dbPath;
    }

    public function getCountry(string $ip): ?string
    {
        $reader = $this->reader;
        if ($reader === null) {
            if ($this->failed) {
                return null;
            }
            $reader = $this->open();
            if ($reader === null) {
                return null;
            }
            $this->reader = $reader;
        }

        $record = $reader->lookup($ip);
        if ($record === null) {
            return null;
        }
        $country = $record['country'] ?? null;
        if (!is_string($country) || $country === '') {
            // Only the top-level "country" string is read (the ipinfo
            // country_asn.mmdb layout); a GeoLite2-style nested
            // country.iso_code record resolves as a miss, like the
            // reference reading a top-level key.
            return null;
        }

        return $country;
    }

    private function open(): ?MmdbReader
    {
        try {
            return new MmdbReader($this->dbPath);
        } catch (MmdbError $error) {
            $this->failed = true;
            if (is_file($this->dbPath) && @unlink($this->dbPath)) {
                error_log("[guard-core] IPInfo database at {$this->dbPath} is corrupted, removing: {$error->getMessage()}");
            } else {
                error_log("[guard-core] IPInfo database at {$this->dbPath} is unavailable: {$error->getMessage()}");
            }

            return null;
        }
    }

    /** Releases the database handle, mirroring IPInfoManager.close. */
    public function close(): void
    {
        $this->reader = null;
    }
}
