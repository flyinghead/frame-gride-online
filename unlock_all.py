"""Unlock all parts, weapons, Liberate Stones, and materials in a FRAME GRIDE VMU save.

Edits only the F_GRIDE.0000 save payload inside a Dreamcast VMU image (.bin):
- Sets all 60 armor parts (3 classes x 4 categories x 5 parts) and categories 5..12 to owned.
- Sets all 32 Liberate Stones (indices 0..31) and 13 Material Stones to the target count (default 99).
- Preserves Knight/Squire names, Frame 0..2 equipped slots, unused gaps, and player stats/save date.
- Recomputes the owned-item display count (+42 / 0x2aa), the inner 32-bit byte-sum checksum (+344 / 0x3d8),
  and the VMU directory header CRC-16 (0x46).
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from vmu_tool import BLOCK, VmuFile, crc_ok, list_files, read_file, save_length, with_fixed_crc

SAVE_NAME = "F_GRIDE.0000"
DATA_OFFSET = 0x280
DATA_SIZE = 348
OWNED_COUNT_REL = 42   # 0x2AA in F_GRIDE.0000
INNER_SUM_REL = 344    # 0x3D8 in F_GRIDE.0000

# Regions inside the 348-byte save payload (relative to DATA_OFFSET = 0x280).
ARMOR_RANGE = (43, 103)     # 0x2AB..0x2E6: 3 classes x 4 armor cats [0,1,2,4] x 5 parts
CAT5_7_RANGE = (103, 127)   # 0x2E7..0x2FE: categories 5, 6, 7 (8 entries each)
CAT8_RANGE = (127, 135)     # 0x2FF..0x306: category 8 (8 entries, clamped 0..99 by game)
CAT9_RANGE = (135, 139)     # 0x307..0x30A: category 9 (4 entries; 139..143 unused gap)
CAT10_RANGE = (143, 151)    # 0x30F..0x316: category 10 (8 entries)
CAT11_RANGE = (151, 159)    # 0x317..0x31E: category 11 (8 entries, omitted by owned count)
CAT12_RANGE = (159, 163)    # 0x31F..0x322: category 12 (4 entries; 163..167 unused gap)
STONES_RANGE = (167, 199)   # 0x327..0x346: 32 Liberate Stones (0..99)
MATERIALS_RANGE = (199, 212)  # 0x347..0x353: 13 Material Stones (0..99)
RECORDS_REL = 268             # 0x38C..0x3BB: 4 x (matches, losses, wins) LE u32 [1P, VS, NET, TOTAL]

MAX_STACK = 99
MAX_RECORD = 9999             # 0x270F clamp in 0x8c08f16c & developer preset 0x8c0c3f34


def inner_checksum(data_section: bytes) -> int:
    """Compute the game's inner 32-bit unsigned byte sum over the first 344 payload bytes."""
    if len(data_section) < INNER_SUM_REL + 4:
        raise ValueError(f"payload too short ({len(data_section)} bytes, expected >= {DATA_SIZE})")
    return sum(data_section[:INNER_SUM_REL]) & 0xFFFFFFFF


def inner_checksum_ok(save_bytes: bytes) -> bool:
    """Return True if the inner F_GRIDE.0000 checksum at 0x3D8 matches the payload."""
    data_offset = _save_data_offset(save_bytes)
    payload = save_bytes[data_offset:data_offset + DATA_SIZE]
    if len(payload) != DATA_SIZE:
        return False
    stored = struct.unpack_from("<I", payload, INNER_SUM_REL)[0]
    return inner_checksum(payload) == stored


def count_owned_items(data_section: bytes) -> int:
    """Match the game's owned-item summary counter (0x8c08f62a + 0x8c08f6e8).

    Counts entries > 0 across armor, categories 5..10, category 12, and Liberate Stones;
    excludes category 11 and raw Material Stones.
    """
    counted_ranges = (
        ARMOR_RANGE,
        CAT5_7_RANGE,
        CAT8_RANGE,
        CAT9_RANGE,
        CAT10_RANGE,
        CAT12_RANGE,
        STONES_RANGE,
    )
    return sum(1 for lo, hi in counted_ranges for b in data_section[lo:hi] if b > 0)


def _save_data_offset(save_bytes: bytes) -> int:
    icons = struct.unpack_from("<H", save_bytes, 0x40)[0]
    return 0x80 + BLOCK * icons


def _fill_range(buf: bytearray, bounds: tuple[int, int], value: int) -> None:
    lo, hi = bounds
    buf[lo:hi] = bytes([value]) * (hi - lo)


RECORD_GROUPS = 4  # 1P, VS, NET, TOTAL


def _set_records(payload: bytearray, wins: int | None, losses: int | None) -> None:
    """Write wins and/or losses into every record group; matches become wins + losses (at most MAX_RECORD).
    A value left as None keeps what the save already holds."""
    values = list(struct.unpack_from(f"<{RECORD_GROUPS * 3}I", payload, RECORDS_REL))
    for group in range(RECORD_GROUPS):
        _matches, old_losses, old_wins = values[group * 3:group * 3 + 3]
        new_wins = old_wins if wins is None else wins
        new_losses = old_losses if losses is None else losses
        values[group * 3:group * 3 + 3] = [min(MAX_RECORD, new_wins + new_losses), new_losses, new_wins]
    struct.pack_into(f"<{RECORD_GROUPS * 3}I", payload, RECORDS_REL, *values)


def _check_record_options(max_records: bool, wins: int | None, losses: int | None) -> None:
    if max_records and (wins is not None or losses is not None):
        raise ValueError("use either max_records or wins/losses, not both")
    for name, val in (("wins", wins), ("losses", losses)):
        if val is not None and not 0 <= val <= MAX_RECORD:
            raise ValueError(f"{name} must be in 0..{MAX_RECORD}, got {val}")


def unlock_save_bytes(
    save_bytes: bytes,
    *,
    stone_count: int = MAX_STACK,
    material_count: int = MAX_STACK,
    cat8_value: int = 1,
    max_records: bool = False,
    wins: int | None = None,
    losses: int | None = None,
) -> bytes:
    """Return a copy of raw F_GRIDE.0000 bytes with all items unlocked and checksums fixed.

    max_records sets every record group to 9999 matches, 0 losses, 9999 wins. wins / losses set those counts instead
    (0..9999 each; the other one keeps its saved value when left as None)."""
    for name, val in (("stone_count", stone_count), ("material_count", material_count), ("cat8_value", cat8_value)):
        if not 1 <= val <= MAX_STACK:
            raise ValueError(f"{name} must be in 1..{MAX_STACK}, got {val}")
    _check_record_options(max_records, wins, losses)

    data_offset = _save_data_offset(save_bytes)
    expected_len = data_offset + DATA_SIZE
    actual_len = save_length(save_bytes)
    if data_offset != DATA_OFFSET or actual_len != expected_len or len(save_bytes) < expected_len:
        raise ValueError(
            f"unexpected F_GRIDE save layout: data_offset=0x{data_offset:x}, "
            f"save_length={actual_len}, len={len(save_bytes)}"
        )

    payload = bytearray(save_bytes[data_offset:data_offset + DATA_SIZE])
    for bounds in (ARMOR_RANGE, CAT5_7_RANGE, CAT9_RANGE, CAT10_RANGE, CAT11_RANGE, CAT12_RANGE):
        _fill_range(payload, bounds, 1)
    _fill_range(payload, CAT8_RANGE, cat8_value)
    _fill_range(payload, STONES_RANGE, stone_count)
    _fill_range(payload, MATERIALS_RANGE, material_count)
    if max_records:
        _set_records(payload, MAX_RECORD, 0)
    elif wins is not None or losses is not None:
        _set_records(payload, wins, losses)

    payload[OWNED_COUNT_REL] = min(255, count_owned_items(payload))
    struct.pack_into("<I", payload, INNER_SUM_REL, inner_checksum(payload))

    updated = bytearray(save_bytes)
    updated[data_offset:data_offset + DATA_SIZE] = payload
    return with_fixed_crc(bytes(updated))


def write_vmu_file(image: bytes, vmu_file: VmuFile, data: bytes) -> bytes:
    """Write a VmuFile payload back into its descending blocks in a 128 KB VMU image."""
    expected_bytes = vmu_file.blocks * BLOCK
    if len(data) != expected_bytes:
        raise ValueError(f"expected {expected_bytes} bytes for {vmu_file.name}, got {len(data)}")
    out = bytearray(image)
    for n in range(vmu_file.blocks):
        blk = vmu_file.first_block - n
        if blk < 0 or (blk + 1) * BLOCK > len(out):
            raise ValueError(f"block {blk} out of bounds for VMU image")
        out[blk * BLOCK:(blk + 1) * BLOCK] = data[n * BLOCK:(n + 1) * BLOCK]
    return bytes(out)


def unlock_vmu_image(
    image: bytes,
    *,
    file_name: str = SAVE_NAME,
    stone_count: int = MAX_STACK,
    material_count: int = MAX_STACK,
    cat8_value: int = 1,
    max_records: bool = False,
    wins: int | None = None,
    losses: int | None = None,
) -> bytes:
    """Unlock all items inside ``file_name`` in a VMU card image and return updated image bytes."""
    matches = [f for f in list_files(image) if f.name == file_name]
    if not matches:
        raise FileNotFoundError(f"{file_name} not found in VMU image")
    vmu_file = matches[0]
    raw_save = read_file(image, vmu_file)
    if not crc_ok(raw_save) or not inner_checksum_ok(raw_save):
        raise ValueError(f"{file_name} failed CRC or inner checksum verification before edit")
    unlocked = unlock_save_bytes(
        raw_save,
        stone_count=stone_count,
        material_count=material_count,
        cat8_value=cat8_value,
        max_records=max_records,
        wins=wins,
        losses=losses,
    )
    return write_vmu_file(image, vmu_file, unlocked)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("src", type=Path, help="source VMU .bin image (left untouched unless equal to dst)")
    parser.add_argument("dst", type=Path, help="destination VMU .bin image to write")
    parser.add_argument("--stone-count", type=int, default=MAX_STACK, help="count for all 32 Liberate Stones (1..99)")
    parser.add_argument("--material-count", type=int, default=MAX_STACK, help="count for all 13 Materials (1..99)")
    parser.add_argument("--cat8-value", type=int, default=1, help="count for category 8 items (1..99, default 1)")
    parser.add_argument("--max-records", action="store_true",
                        help="set 1P / VS / NET / TOTAL battle records to 9999 matches, 0 losses, 9999 wins")
    parser.add_argument("--wins", type=int, help="set the wins of every record group (0..9999)")
    parser.add_argument("--losses", type=int, help="set the losses of every record group (0..9999)")
    args = parser.parse_args()
    try:
        _check_record_options(args.max_records, args.wins, args.losses)
    except ValueError as exc:
        parser.error(str(exc))

    src_bytes = args.src.read_bytes()
    out_bytes = unlock_vmu_image(
        src_bytes,
        stone_count=args.stone_count,
        material_count=args.material_count,
        cat8_value=args.cat8_value,
        max_records=args.max_records,
        wins=args.wins,
        losses=args.losses,
    )
    args.dst.parent.mkdir(parents=True, exist_ok=True)
    args.dst.write_bytes(out_bytes)
    print(
        f"Unlocked {SAVE_NAME}: wrote {args.dst} ({len(out_bytes)} bytes, "
        f"stones={args.stone_count}, materials={args.material_count}, "
        f"cat8={args.cat8_value}, max_records={args.max_records}, wins={args.wins}, losses={args.losses})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
