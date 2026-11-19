import os
import struct
import unittest
from pathlib import Path

from test_vmu_tool import make_image
from unlock_all import (
    DATA_OFFSET,
    DATA_SIZE,
    INNER_SUM_REL,
    MAX_RECORD,
    OWNED_COUNT_REL,
    RECORDS_REL,
    SAVE_NAME,
    count_owned_items,
    inner_checksum,
    inner_checksum_ok,
    unlock_save_bytes,
    unlock_vmu_image,
)
from vmu_tool import BLOCK, crc_ok, list_files, read_file, with_fixed_crc


def make_fgride_save(data_size: int = DATA_SIZE) -> bytes:
    """Build a synthetic F_GRIDE.0000 save payload with valid inner checksum and VMU CRC."""
    body = bytearray(DATA_OFFSET + data_size)
    struct.pack_into("<H", body, 0x40, 1)  # 1 VMU icon
    struct.pack_into("<I", body, 0x48, data_size)
    payload = bytearray(data_size)
    payload[0:6] = b"KNIGHT"
    payload[21:27] = b"SQUIRE"
    payload[212:266] = bytes([0xAA] * 54)   # equipped slots / stones
    payload[266:344] = bytes([0x55] * 78)   # stats / date
    payload[OWNED_COUNT_REL] = count_owned_items(payload)
    struct.pack_into("<I", payload, INNER_SUM_REL, inner_checksum(payload))
    body[DATA_OFFSET:DATA_OFFSET + data_size] = payload
    padded = bytes(body) + bytes(-len(body) % BLOCK)
    return with_fixed_crc(padded)


class TestUnlockAll(unittest.TestCase):
    def test_unlocks_expected_ranges_and_preserves_equipment_and_stats(self) -> None:
        raw = make_fgride_save()
        unlocked = unlock_save_bytes(raw, stone_count=50, material_count=99, cat8_value=1)

        self.assertTrue(crc_ok(unlocked))
        self.assertTrue(inner_checksum_ok(unlocked))

        before = raw[DATA_OFFSET:DATA_OFFSET + DATA_SIZE]
        after = unlocked[DATA_OFFSET:DATA_OFFSET + DATA_SIZE]

        # Preserved sections
        self.assertEqual(after[0:42], before[0:42])         # Knight & Squire names
        self.assertEqual(after[139:143], b"\x00" * 4)      # unused gap after cat 9
        self.assertEqual(after[163:167], b"\x00" * 4)      # unused gap after cat 12
        self.assertEqual(after[212:266], before[212:266])  # Frame 0..2 equipment + stone slots
        self.assertEqual(after[266:344], before[266:344])  # stats / currency / save date

        # Unlocked sections
        self.assertEqual(after[43:103], b"\x01" * 60)      # 60 armor parts
        self.assertEqual(after[103:135], b"\x01" * 32)     # cat 5..8
        self.assertEqual(after[135:139], b"\x01" * 4)      # cat 9
        self.assertEqual(after[143:159], b"\x01" * 16)     # cat 10..11
        self.assertEqual(after[159:163], b"\x01" * 4)      # cat 12
        self.assertEqual(after[167:199], bytes([50] * 32)) # 32 Liberate Stones
        self.assertEqual(after[199:212], bytes([99] * 13)) # 13 Material Stones
        self.assertEqual(after[OWNED_COUNT_REL], 60 + 48 + 32)  # 140

    def test_vmu_round_trip_updates_both_checksums(self) -> None:
        raw = make_fgride_save()
        image = make_image(raw, name=SAVE_NAME)
        unlocked_image = unlock_vmu_image(image, stone_count=99, material_count=99)

        files = list_files(unlocked_image)
        self.assertEqual([f.name for f in files], [SAVE_NAME])
        extracted = read_file(unlocked_image, files[0])
        self.assertTrue(crc_ok(extracted))
        self.assertTrue(inner_checksum_ok(extracted))

    def test_rejects_corrupt_inner_checksum(self) -> None:
        raw = bytearray(make_fgride_save())
        raw[DATA_OFFSET + 43] ^= 0x01
        bad_save = with_fixed_crc(bytes(raw))
        self.assertTrue(crc_ok(bad_save))
        self.assertFalse(inner_checksum_ok(bad_save))
        with self.assertRaises(ValueError):
            unlock_vmu_image(make_image(bad_save, name=SAVE_NAME))

    def test_real_story_save_unlock_preserves_header_and_loadout(self) -> None:
        path = Path(os.environ.get("FG_SAVE_IMAGE", ""))
        if not path.is_file():
            self.skipTest("set FG_SAVE_IMAGE to a memory-card image with an F_GRIDE.0000 save to run this test")
        src_img = path.read_bytes()
        unlocked_img = unlock_vmu_image(src_img)

        src_save = read_file(src_img, list_files(src_img)[0])
        dst_save = read_file(unlocked_img, list_files(unlocked_img)[0])

        self.assertTrue(inner_checksum_ok(src_save))
        self.assertTrue(inner_checksum_ok(dst_save))
        self.assertTrue(crc_ok(dst_save))
        self.assertEqual(dst_save[:DATA_OFFSET], with_fixed_crc(dst_save)[:DATA_OFFSET])
        self.assertEqual(dst_save[0x354:0x3D8], src_save[0x354:0x3D8])
        self.assertEqual(dst_save[0x2AA], 140)

    def test_max_records_sets_9999_wins_and_keeps_checksums(self) -> None:
        raw = make_fgride_save()
        unlocked = unlock_save_bytes(raw, max_records=True)
        self.assertTrue(crc_ok(unlocked))
        self.assertTrue(inner_checksum_ok(unlocked))
        after = unlocked[DATA_OFFSET:DATA_OFFSET + DATA_SIZE]
        self.assertEqual(struct.unpack_from("<12I", after, RECORDS_REL), (MAX_RECORD, 0, MAX_RECORD) * 4)
        self.assertEqual(after[316:344], raw[DATA_OFFSET + 316:DATA_OFFSET + 344])  # post-record fields preserved

    def records(self, save: bytes) -> tuple[int, ...]:
        return struct.unpack_from("<12I", save, DATA_OFFSET + RECORDS_REL)

    def test_wins_and_losses_set_every_record_group_with_matches_as_their_sum(self) -> None:
        unlocked = unlock_save_bytes(make_fgride_save(), wins=120, losses=30)
        self.assertEqual(self.records(unlocked), (150, 30, 120) * 4)
        self.assertTrue(crc_ok(unlocked))
        self.assertTrue(inner_checksum_ok(unlocked))

    def test_matches_stop_at_9999_when_wins_plus_losses_is_larger(self) -> None:
        unlocked = unlock_save_bytes(make_fgride_save(), wins=MAX_RECORD, losses=MAX_RECORD)
        self.assertEqual(self.records(unlocked), (MAX_RECORD, MAX_RECORD, MAX_RECORD) * 4)

    def test_only_losses_keeps_the_saved_wins(self) -> None:
        first = unlock_save_bytes(make_fgride_save(), wins=10, losses=0)
        second = unlock_save_bytes(first, losses=5)
        self.assertEqual(self.records(second), (15, 5, 10) * 4)

    def test_rejects_record_values_out_of_range(self) -> None:
        for kwargs in ({"wins": MAX_RECORD + 1}, {"losses": -1}):
            with self.assertRaises(ValueError):
                unlock_save_bytes(make_fgride_save(), **kwargs)

    def test_max_records_cannot_be_combined_with_wins_or_losses(self) -> None:
        with self.assertRaises(ValueError):
            unlock_save_bytes(make_fgride_save(), max_records=True, losses=3)


if __name__ == "__main__":
    unittest.main()
