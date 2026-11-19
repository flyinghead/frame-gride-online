"""Read a Dreamcast memory card image (VMU, 128 KB) and its game save files.

    uv run python .\\vmu_tool.py play-work\\offline-data\\T34201M_vmu_save_A1.bin            # list files
    uv run python .\\vmu_tool.py play-work\\offline-data\\T34201M_vmu_save_A1.bin --extract F_GRIDE.0000 out.bin

Layout: 256 blocks of 512 bytes. Block 255 is the root, 254 the FAT, 253 down to 241 the directory (32-byte
entries). Files are allocated from the top down. Flycast's FAT can show a fresh file's blocks as free, so a file
is read here as `blocks` consecutive blocks going down from its first block.
The save header is 0x80 bytes plus 512 bytes per icon frame; its CRC (offset 0x46, little endian) is a CRC-16
(polynomial 0x1021, start 0) over header + icons + data with the CRC field set to zero.
"""
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path

BLOCK = 512
ROOT_BLOCK = 255
DIR_FIRST, DIR_LAST = 253, 241
FILE_TYPES = (0x33, 0xCC)  # data file, game file
HEADER_SIZE = 0x80
ICON_SIZE = 512
CRC_OFFSET = 0x46


@dataclass(frozen=True)
class VmuFile:
    name: str
    first_block: int
    blocks: int


def list_files(image: bytes) -> list[VmuFile]:
    files = []
    for blk in range(DIR_FIRST, DIR_LAST - 1, -1):
        for i in range(16):
            entry = image[blk * BLOCK + i * 32: blk * BLOCK + i * 32 + 32]
            if entry[0] in FILE_TYPES:
                name = entry[4:16].decode("ascii", "replace").rstrip("\x00 ")
                files.append(VmuFile(name, struct.unpack("<H", entry[2:4])[0], struct.unpack("<H", entry[0x18:0x1A])[0]))
    return files


def read_file(image: bytes, vmu_file: VmuFile) -> bytes:
    """Bytes of a save file: its blocks, counted down from the first block."""
    return b"".join(image[(vmu_file.first_block - n) * BLOCK:(vmu_file.first_block - n + 1) * BLOCK]
                    for n in range(vmu_file.blocks))


def save_crc(data: bytes) -> int:
    """CRC-16 (0x1021) of a save, with the CRC field read as zero."""
    buf = bytearray(data)
    buf[CRC_OFFSET:CRC_OFFSET + 2] = b"\x00\x00"
    crc = 0
    for byte in buf:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def save_length(data: bytes) -> int:
    """Header + icon frames + data size: the part of a save the CRC covers."""
    icons = struct.unpack("<H", data[0x40:0x42])[0]
    data_size = struct.unpack("<I", data[0x48:0x4C])[0]
    return HEADER_SIZE + ICON_SIZE * icons + data_size


def crc_ok(data: bytes) -> bool:
    covered = data[:save_length(data)]
    return struct.unpack("<H", covered[CRC_OFFSET:CRC_OFFSET + 2])[0] == save_crc(covered)


def with_fixed_crc(data: bytes) -> bytes:
    """Copy of a save with its CRC recomputed (use after editing the data part)."""
    length = save_length(data)
    crc = save_crc(data[:length])
    return data[:CRC_OFFSET] + struct.pack("<H", crc) + data[CRC_OFFSET + 2:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", type=Path)
    parser.add_argument("--extract", metavar="NAME")
    parser.add_argument("output", nargs="?", type=Path)
    args = parser.parse_args()
    image = args.image.read_bytes()
    files = list_files(image)
    if args.extract is None:
        for f in files:
            data = read_file(image, f)
            print(f"{f.name:<14} first block {f.first_block:3d}, {f.blocks} blocks, CRC {'ok' if crc_ok(data) else 'BAD'}")
        return 0
    match = [f for f in files if f.name == args.extract]
    if not match or args.output is None:
        raise SystemExit("name not found, or no output path given")
    args.output.write_bytes(read_file(image, match[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
