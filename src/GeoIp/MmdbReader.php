<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\GeoIp;

/**
 * Minimal pure-PHP MaxMind MMDB reader. The port ships no geo dependency
 * (the reference's `maxminddb` extra and guard-core-go's
 * `maxminddb-golang` are native libraries), so this reader implements the
 * subset of the MMDB format the engine needs: the metadata block, a binary
 * search over the record-size 24/28/32 search tree (IPv4 and IPv6), and
 * data-section decoding down to the record map.
 *
 * Only well-formed databases are supported; any structural surprise raises
 * MmdbError so GeoIpManager can fail soft.
 */
final class MmdbReader
{
    private const METADATA_MARKER = "\xAB\xCD\xEFMaxMind.com";

    private const DATA_SEPARATOR_SIZE = 16;

    private string $data;

    private int $nodeCount;

    private int $recordSize;

    private int $ipVersion;

    private int $treeSize;

    /**
     * @throws MmdbError when the file is unreadable, truncated, or not an
     *                   MMDB database
     */
    /** The metadata node count, the reference entry_count. */
    public function nodeCount(): int
    {
        return $this->nodeCount;
    }

    public function __construct(string $path)
    {
        $data = @file_get_contents($path);
        if ($data === false) {
            throw new MmdbError("unable to read MMDB file '{$path}'");
        }
        $marker = strrpos($data, self::METADATA_MARKER);
        if ($marker === false) {
            throw new MmdbError("not an MMDB database: '{$path}'");
        }
        $this->data = $data;

        $decoder = new MmdbDecoder($data, $marker + strlen(self::METADATA_MARKER));
        $metadata = $decoder->decode();
        if (!is_array($metadata)
            || !isset($metadata['node_count'], $metadata['record_size'], $metadata['ip_version'])
            || !is_int($metadata['node_count'])
            || !is_int($metadata['record_size'])
            || !is_int($metadata['ip_version'])
        ) {
            throw new MmdbError("malformed MMDB metadata in '{$path}'");
        }
        if (!in_array($metadata['record_size'], [24, 28, 32], true)) {
            throw new MmdbError("unsupported MMDB record size {$metadata['record_size']} in '{$path}'");
        }
        $this->nodeCount = $metadata['node_count'];
        $this->recordSize = $metadata['record_size'];
        $this->ipVersion = $metadata['ip_version'];
        $recordBytes = intdiv($this->recordSize, 8);
        $this->treeSize = $this->nodeCount * $recordBytes * 2;
    }

    /**
     * Resolves the record map for the ip, or null when the address is
     * unparseable or falls outside the database.
     *
     * @return array<string, mixed>|null
     */
    public function lookup(string $ip): ?array
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        if ($this->ipVersion === 6 && strlen($packed) === 4) {
            // IPv4 addresses live in an IPv6 database under the IPv4-mapped
            // prefix: 96 zero bits first (the MaxMind convention).
            $packed = str_repeat("\x00", 12) . $packed;
        } elseif ($this->ipVersion === 4 && strlen($packed) === 16) {
            return null;
        }

        $node = 0;
        $bytes = $packed;
        $totalBits = strlen($bytes) * 8;
        for ($i = 0; $i < $totalBits && $node < $this->nodeCount; $i++) {
            $bit = (ord($bytes[$i >> 3]) >> (7 - ($i & 7))) & 1;
            $node = $this->readNodeRecord($node, $bit);
        }

        if ($node === $this->nodeCount) {
            return null; // not found
        }
        if ($node > $this->nodeCount) {
            $decoded = (new MmdbDecoder($this->data, $this->treeSize + self::DATA_SEPARATOR_SIZE))
                ->decodeAt($node - $this->nodeCount - self::DATA_SEPARATOR_SIZE);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return null;
    }

    private function readNodeRecord(int $node, int $bit): int
    {
        $recordBytes = intdiv($this->recordSize, 8);
        $offset = $node * $recordBytes * 2 + ($bit === 1 ? $recordBytes : 0);
        $bytes = substr($this->data, $offset, 4);
        if (strlen($bytes) !== 4) {
            throw new MmdbError('truncated MMDB search tree');
        }
        $b0 = ord($bytes[0]);
        $b1 = ord($bytes[1]);
        $b2 = ord($bytes[2]);
        $b3 = ord($bytes[3]);

        return match ($this->recordSize) {
            24 => ($b0 << 16) | ($b1 << 8) | $b2,
            28 => (($b0 & 0xF0) << 20) | ($b1 << 16) | ($b2 << 8) | $b3,
            32 => ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3,
            default => throw new MmdbError("unsupported MMDB record size {$this->recordSize}"),
        };
    }
}
