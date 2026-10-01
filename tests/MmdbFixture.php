<?php

declare(strict_types=1);

/**
 * Shared in-test MMDB fixture builder (used by the geo suites): a minimal
 * but spec-valid MMDB database (record size 24, IPv4) mapping prefixes to
 * ISO country codes, in the ipinfo country_asn.mmdb layout the engine
 * reads (top-level "country" string records).
 *
 * @param array<string, string> $entries prefix => country code
 */
/**
 * Writes a minimal but spec-valid MMDB database (record size 24, IPv4)
 * mapping the given prefixes to ISO country codes, and returns the path.
 * Only top-level "country" string records are written: the ipinfo
 * country_asn.mmdb layout the reference get_country reads.
 *
 * @param array<string, string> $entries
 */
function buildTestMmdb(array $entries): string
{
    // Build the binary search tree as nested arrays; a leaf stores its
    // country code under the '!' key.
    $root = [];
    foreach ($entries as $prefix => $code) {
        [$network, $bits] = explode('/', $prefix);
        $raw = unpack('C4', (string) inet_pton((string) $network));
        $node = &$root;
        for ($i = 0; $i < (int) $bits; $i++) {
            $bit = ($raw[intdiv($i, 8) + 1] >> (7 - ($i % 8))) & 1;
            $key = $bit === 1 ? 'r' : 'l';
            if (!isset($node[$key]) || !is_array($node[$key])) {
                $node[$key] = [];
            }
            $node = &$node[$key];
        }
        $node['!'] = $code;
        unset($node);
    }

    // Data section first: one {"country": code} map per unique code, so
    // the leaf records can point at stable offsets.
    $offsets = [];
    $dataSection = '';
    foreach ($entries as $code) {
        if (isset($offsets[$code])) {
            continue;
        }
        $offsets[$code] = strlen($dataSection);
        $dataSection .= "\xE1" . chr(0x40 | 7) . 'country' . chr(0x40 | strlen($code)) . $code;
    }

    // Wrap the tree into node objects and BFS-index the internal nodes
    // (node 0 is the root); country-carrying slots emit data pointers
    // instead of node indexes.
    $build = static function (array $node) use (&$build): object {
        $left = $node['l'] ?? null;
        $right = $node['r'] ?? null;

        return (object) [
            'country' => $node['!'] ?? null,
            'left' => is_array($left) ? $build($left) : null,
            'right' => is_array($right) ? $build($right) : null,
        ];
    };
    $rootObj = $build($root);

    $index = new SplObjectStorage();
    $index[$rootObj] = 0;
    $nodes = [$rootObj];
    $queue = [$rootObj];
    while ($queue !== []) {
        $current = array_shift($queue);
        foreach (['left', 'right'] as $side) {
            $child = $current->{$side};
            if ($child === null || $child->country !== null || $index->contains($child)) {
                continue;
            }
            $index[$child] = count($nodes);
            $nodes[] = $child;
            $queue[] = $child;
        }
    }
    $nodeCount = count($nodes);

    $emitRecord = static function (?object $child) use ($index, $nodeCount, $offsets): string {
        if ($child === null) {
            $value = 0;
        } elseif ($child->country !== null) {
            // Data section pointers are measured from the separator start,
            // so the record carries the 16 separator bytes as well.
            $value = $nodeCount + 16 + $offsets[$child->country];
        } else {
            $value = $index[$child];
        }

        return chr(($value >> 16) & 0xFF) . chr(($value >> 8) & 0xFF) . chr($value & 0xFF);
    };
    $treeBytes = '';
    foreach ($nodes as $node) {
        $treeBytes .= $emitRecord($node->left);
        $treeBytes .= $emitRecord($node->right);
    }

    $mmdbString = static fn (string $s): string => chr(0x40 | strlen($s)) . $s;
    $mmdbUint16 = static fn (int $v): string => "\xA2" . chr($v >> 8) . chr($v & 0xFF);
    $mmdbUint32 = static fn (int $v): string => "\xC4" . pack('N', $v);

    $meta = "\xE9"; // map, 9 entries
    $meta .= $mmdbString('node_count') . $mmdbUint32($nodeCount);
    $meta .= $mmdbString('record_size') . $mmdbUint16(24);
    $meta .= $mmdbString('ip_version') . $mmdbUint16(4);
    $meta .= $mmdbString('database_type') . $mmdbString('GuardCore-Test-Country');
    // languages: extended type 11 (array) with one element. The first
    // control byte is the extended-type marker (0x01), the second byte
    // carries (11 - 7) << 3 | size.
    $meta .= $mmdbString('languages') . "\x01" . "\x21" . $mmdbString('en');
    $meta .= $mmdbString('binary_format_major_version') . $mmdbUint16(2);
    $meta .= $mmdbString('binary_format_minor_version') . $mmdbUint16(0);
    $meta .= $mmdbString('build_epoch') . $mmdbUint32(1700000000);
    $meta .= $mmdbString('description') . "\xE1" . $mmdbString('en') . $mmdbString('GuardCore test database');

    $out = $treeBytes . str_repeat("\x00", 16) . $dataSection . "\xAB\xCD\xEFMaxMind.com" . $meta;
    $path = (string) tempnam(sys_get_temp_dir(), 'mmdb');
    file_put_contents($path, $out);

    return $path;
}
