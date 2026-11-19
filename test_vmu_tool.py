import struct
import unittest

from vmu_tool import BLOCK, crc_ok, list_files, read_file, save_length, with_fixed_crc


def make_save(data_size: int = 100, icons: int = 1) -> bytes:
    """A save with a valid CRC: header + icons + data, padded to whole blocks."""
    body = bytearray(0x80 + 512 * icons + data_size)
    struct.pack_into("<H", body, 0x40, icons)
    struct.pack_into("<I", body, 0x48, data_size)
    body[0x80 + 512 * icons:] = bytes(range(data_size))
    padded = bytes(body) + bytes(-len(body) % BLOCK)
    return with_fixed_crc(padded)


def make_image(save: bytes, name: str = "TEST.0000", first_block: int = 199) -> bytes:
    image = bytearray(256 * BLOCK)
    blocks = len(save) // BLOCK
    for n in range(blocks):
        image[(first_block - n) * BLOCK:(first_block - n + 1) * BLOCK] = save[n * BLOCK:(n + 1) * BLOCK]
    entry = bytearray(32)
    entry[0] = 0x33
    struct.pack_into("<H", entry, 2, first_block)
    entry[4:16] = name.encode().ljust(12, b"\x00")
    struct.pack_into("<H", entry, 0x18, blocks)
    image[253 * BLOCK:253 * BLOCK + 32] = entry
    return bytes(image)


class TestVmuTool(unittest.TestCase):
    def test_lists_the_file_in_the_directory(self) -> None:
        files = list_files(make_image(make_save()))
        self.assertEqual([(f.name, f.first_block, f.blocks) for f in files], [("TEST.0000", 199, 2)])

    def test_reads_the_blocks_counting_down_from_the_first_block(self) -> None:
        save = make_save()
        image = make_image(save)
        self.assertEqual(read_file(image, list_files(image)[0]), save)

    def test_a_fresh_save_has_a_good_crc(self) -> None:
        self.assertTrue(crc_ok(make_save()))

    def test_editing_the_data_breaks_the_crc_until_it_is_fixed(self) -> None:
        save = bytearray(make_save())
        save[0x80 + 512 + 5] ^= 0xFF
        self.assertFalse(crc_ok(bytes(save)))
        self.assertTrue(crc_ok(with_fixed_crc(bytes(save))))

    def test_crc_covers_header_icons_and_data_only(self) -> None:
        save = make_save(data_size=100)
        self.assertEqual(save_length(save), 0x80 + 512 + 100)
        padded_change = bytearray(save)
        padded_change[-1] ^= 0xFF  # the zero padding after the data is outside the CRC
        self.assertTrue(crc_ok(bytes(padded_change)))

    def test_real_story_save_is_recognized_when_present(self) -> None:
        import os
        from pathlib import Path
        path = Path(os.environ.get("FG_SAVE_IMAGE", ""))
        if not path.is_file():
            self.skipTest("set FG_SAVE_IMAGE to a memory-card image with an F_GRIDE.0000 save to run this test")
        image = path.read_bytes()
        files = list_files(image)
        self.assertEqual([f.name for f in files], ["F_GRIDE.0000"])
        self.assertTrue(crc_ok(read_file(image, files[0])))


if __name__ == "__main__":
    unittest.main()
