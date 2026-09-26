<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\GeoIp;

/**
 * Data-section (and metadata) decoder over a fixed byte buffer, following
 * the MaxMind DB file format spec: the control byte carries the type in
 * its top three bits and the size in its bottom five; type 0 is the
 * extended-type marker (the next byte holds type minus 7 in its top five
 * bits and the size in its bottom three) and type 1 is a pointer (the
 * size field is repurposed as pointer size in its top two bits and the
 * pointer value in its bottom three).
 */
final class MmdbDecoder
{
    public function __construct(
        private readonly string $data,
        private readonly int $base
    ) {
    }

    /** Decodes the value starting at the decoder base. */
    public function decode(): mixed
    {
        return $this->decodeAt(0);
    }

    /** Decodes the value at an offset relative to the decoder base. */
    public function decodeAt(int $offset): mixed
    {
        $pos = 0;

        return $this->readValue($this->base + $offset, $pos);
    }

    private function readValue(int $offset, int &$pos): mixed
    {
        $ctrl = $this->byteAt($offset);
        $offset++;
        $type = $ctrl >> 5;
        if ($type === 0) {
            $extended = $this->byteAt($offset);
            $offset++;
            $type = ($extended >> 3) + 7;
            $size = $extended & 0x7;
        } else {
            $size = $ctrl & 0x1f;
        }

        if ($type === 1) {
            // Pointer record: the size field is repurposed (top two bits
            // select the additional byte width, bottom three bits start
            // the value); only the pointer bytes are consumed from the
            // stream and the aliased value is decoded in place.
            $width = (($size >> 3) & 0x3) + 1;
            $value = $ctrl & 0x7;
            for ($i = 0; $i < $width; $i++) {
                $value = ($value << 8) | $this->byteAt($offset);
                $offset++;
            }
            $pos = $offset;
            $followPos = 0;

            return $this->readValue($this->base + $value, $followPos);
        }

        if ($size >= 29) {
            $width = [29 => 1, 30 => 2, 31 => 3][$size];
            $size = [29 => 29, 30 => 285, 31 => 65821][$size];
            for ($i = 0; $i < $width; $i++) {
                $size = ($size << 8) | $this->byteAt($offset);
                $offset++;
            }
        }

        switch ($type) {
            case 2: // string (utf-8)
            case 4: // bytes
                $pos = $offset + $size;

                return substr($this->data, $offset, $size);
            case 3: // double
                $pos = $offset + 8;
                $unpack = unpack('E', substr($this->data, $offset, 8));

                return $unpack === false ? null : $unpack[1];
            case 15: // float
                $pos = $offset + 4;
                $unpack = unpack('G', substr($this->data, $offset, 4));

                return $unpack === false ? null : $unpack[1];
            case 5: // uint16
            case 6: // uint32
            case 9: // uint64
            case 10: // uint128
                $pos = $offset + $size;
                $value = 0;
                for ($i = 0; $i < $size; $i++) {
                    $value = ($value * 256) + $this->byteAt($offset + $i);
                }

                return $value;
            case 8: // int32 (sign-extended 32 bit)
                $pos = $offset + $size;
                $value = 0;
                for ($i = 0; $i < $size; $i++) {
                    $value = ($value << 8) | $this->byteAt($offset + $i);
                }
                if ($size === 4 && ($value & 0x80000000) !== 0) {
                    $value -= 4294967296;
                }

                return $value;
            case 7: // map
                $map = [];
                for ($i = 0; $i < $size; $i++) {
                    $key = $this->readValue($offset, $offset);
                    $map[is_string($key) ? $key : ''] = $this->readValue($offset, $offset);
                }
                $pos = $offset;

                return $map;
            case 11: // array
                $array = [];
                for ($i = 0; $i < $size; $i++) {
                    $array[] = $this->readValue($offset, $offset);
                }
                $pos = $offset;

                return $array;
            case 14: // boolean (the size field is the value)
                $pos = $offset;

                return $size === 1;
            default:
                throw new MmdbError("unsupported MMDB data type {$type}");
        }
    }

    private function byteAt(int $offset): int
    {
        if ($offset < 0 || $offset >= strlen($this->data)) {
            throw new MmdbError('truncated MMDB data section');
        }

        return ord($this->data[$offset]);
    }
}

