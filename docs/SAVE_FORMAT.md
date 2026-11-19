# FRAME GRIDE (`T34201M`) VMU Save Structure & Unlock Tool Reference

This document records the Dreamcast VMU save format of *FRAME GRIDE* (`F_GRIDE.0000`) reverse-engineered from the game's main executable `1ST_READ.BIN` (SH-4, read only; addresses below are runtime addresses) and verified with the unmodified disc on Flycast 2.7, together with usage of [`unlock_all.py`](../unlock_all.py) and NET GAME VMU loading.

---

## 1. VMU File & Double Checksums

- **Filename**: `F_GRIDE.0000`
- **Allocation**: 2 VMU blocks (`1024` bytes), starting at `first_block = 199` and stored in descending block order (`199`, then `198`).
- **Logical Save Length (`save_length`)**: `988` bytes (`0x80` VMU directory header + `512` B 1-frame icon = `0x280`, followed by `348` B payload `0x280..0x3DB`).

Editing the payload requires recomputing **two** checksums (without valid values, the game rejects the file):

1. **Inner 32-bit Byte Sum (`0x3D8..0x3DB`, payload `+344`)**:
   - Unsigned 32-bit little-endian sum of the first `344` bytes of the payload (`0x280..0x3D7`):
     ```python
     sum(raw[0x280:0x3D8]) & 0xFFFFFFFF
     ```
   - Verified on a real starter save: sum `0x0000340b` (`13323`) matched the stored LE u32.
2. **VMU Directory Header CRC-16 (`0x46..0x47`)**:
   - Polynomial `0x1021` over the `988`-byte file with `0x46..0x47` zeroed (`vmu_tool.with_fixed_crc`).

---

## 2. `F_GRIDE.0000` Payload Layout (`348` bytes at `0x280..0x3DB`)

Offsets below are given both as **file offset** (`0x280 + rel`) and **payload-relative offset** (`+rel`).

| File Offset | Rel | Size | Field / Meaning | Game Logic / Limits |
| :--- | :--- | :--- | :--- | :--- |
| `0x280..0x294` | `+0` | `21` B | Knight Name (Shift-JIS, NUL-padded) | Preserved |
| `0x295..0x2A9` | `+21` | `21` B | Squire Name (Shift-JIS, NUL-padded) | Preserved |
| `0x2AA` | `+42` | `1` B | Owned-item summary count (`0x8c08f62a + 0x8c08f6e8`) | Counts entries `> 0` across armor, cats `5..10`, `cat 12`, and `32` Squires (`14` on starter save, `140` when all unlocked). Excludes `cat 11` and Materials. |
| `0x2AB..0x2E6` | `+43` | `60` B | Armor Parts (`3` classes × `4` armor cats `[0, 1, 2, 4]` × `5` parts) | `0`/`1` (`0x8c0c402c`). Note `cat 3` is skipped by the game. |
| `0x2E7..0x2EE` | `+103` | `8` B | Category `5` — Guns | `0`/`1` (`8` items: スキアヴォーナ〜ロンクロイム) |
| `0x2EF..0x2F6` | `+111` | `8` B | Category `6` — Swords | `0`/`1` (`8` items: ヴァルムンク〜ルーンメイス) |
| `0x2F7..0x2FE` | `+119` | `8` B | Category `7` — Sub-weapons / Magic Arms | `0`/`1` (`8` items: エクソダスゲート〜ソロモンズローブ) |
| `0x2FF..0x306` | `+127` | `8` B | Category `8` — Shields | Clamped `0..99` at `0x8c08e598`; `1` in dev preset (`0x8c0c456c`) (`8` items: フレイムリーフ〜ランソール) |
| `0x307..0x30A` | `+135` | `4` B | Category `9` — Elemental Stones | `0`/`1` (`4` items: ファイア / アクア / ウインド / アースストーン) |
| `0x30B..0x30E` | `+139` | `4` B | Unused padding gap | Keep `0x00` |
| `0x30F..0x316` | `+143` | `8` B | Category `10` — Ability Stones (Slot 1) | `0`/`1` (`8` items: スマッシュ〜フレームストーン) |
| `0x317..0x31E` | `+151` | `8` B | Category `11` — Ability Stones (Slot 2) | `0`/`1` (`8` items; omitted by `+42` owned counter) |
| `0x31F..0x322` | `+159` | `4` B | Category `12` — Misc/Attribute group | `0`/`1` (`4` items active in `0x8c0c456c`) |
| `0x323..0x326` | `+163` | `4` B | Unused padding gap | Keep `0x00` |
| `0x327..0x346` | `+167` | `32` B | Squires (`0..31`, RAM `0x8c3c8914`) | Clamped `0..99` (`0x8c08f03a`); `50` in dev preset, `99` max |
| `0x347..0x353` | `+199` | `13` B | Material Stones (`0..12`, RAM `0x8c3c89d0`) | Clamped `0..99` (`0x8c08f0c4`); `50` in dev preset, `99` max |
| `0x354..0x37A` | `+212` | `39` B | Frame `0..2` equipped part indices (`3 × 13`) | Unused Frames contain `0xFF` — **do not overwrite** |
| `0x37B..0x389` | `+251` | `15` B | Frame `0..2` equipped Squire slots (`3 × 5`) | Empty slots contain `0xFF` — **do not overwrite** |
| `0x38A` | `+266` | `1` B | Misc / frame state byte | Preserved (`0x06` on starter) |
| `0x38B` | `+267` | `1` B | Story stage progress (`0x8c08f292`) | `0` on starter, `9` in dev preset |
| `0x38C..0x3BB` | `+268` | `48` B | Battle Records: `4` × `(matches, losses, wins)` LE u32 (`1P`, `VS`, `NET`, `TOTAL`) | Clamped to `9999` (`0x270F`) at `0x8c08f1a0` and `"FINAL SUPER FG 2"` (`0x8c0c3f34`) |
| `0x3BC..0x3D7` | `+316` | `28` B | Counters / save timestamp (`0x3D0..0x3D7`) | Preserved |
| `0x3D8..0x3DB` | `+344` | `4` B | Inner checksum (`LE u32`) | `sum(raw[0x280:0x3D8]) & 0xFFFFFFFF` |

### Related Developer Debug Preset in `1ST_READ.BIN`

Function `0x8c08fc60` (`"FINAL SUPER FG 2"` / `"1999/06/21"`) initializes a test profile using:
- Armor unlock table: `0x8c0c402c` (all `60` slots active)
- Category `5..12` table: `0x8c0c456c` (`8, 8, 8, 8, 4, 8, 8, 4` active)
- Battle record preset `0x8c0c3f34`: `[9999, 0, 9999]` for all 4 record groups (`1P`, `VS`, `NET`, `TOTAL`)
- `32` Squires set to `50` and `13` Materials set to `50` (`0..99` max is `99`)

---

## 3. Using `unlock_all.py`

Always pass a source VMU image and a destination copy path (the source is never overwritten). Flycast keeps the card of port A slot 1 as `T34201M_vmu_save_A1.bin` in its data folder. Close Flycast before copying it.

```powershell
# Unlock all parts, weapons, stones, Squires (x99), and Materials (x99)
uv run python unlock_all.py my-card-backup.bin unlocked/T34201M_vmu_save_A1.bin

# Also max out 1P / VS / NET / TOTAL battle records to 9999 / 9999
uv run python unlock_all.py my-card-backup.bin unlocked/T34201M_vmu_save_A1.bin --max-records
```

The card must already hold an `F_GRIDE.0000` save: start the story mode once, enter a name and save. The tool edits that save; it does not create one.

Options:
- `--stone-count N` (`1..99`, default `99`): Quantity for all `32` Squires
- `--material-count N` (`1..99`, default `99`): Quantity for all `13` Material Stones
- `--cat8-value N` (`1..99`, default `1`): Value for Category 8 (Shields)
- `--max-records`: Set `1P`, `VS`, `NET`, and `TOTAL` battle records (`0x38C..0x3BB`) to `9999` matches / `0` losses / `9999` wins (`0x270F`)
- `--wins N`, `--losses N` (`0..9999` each): Set the wins and/or losses of all four record groups. Matches become wins + losses, capped at `9999`. A count you leave out keeps its saved value. Cannot be combined with `--max-records`. (Checked on the file and its checksums; how the game shows a record with losses has not been checked on screen yet.)

Verify a modified card image with `vmu_tool.py`:

```powershell
uv run python vmu_tool.py unlocked/T34201M_vmu_save_A1.bin
```

---

## 4. Loading Unlocked VMU Data into NET GAME

Two important runtime behaviors were confirmed on Flycast:

1. **Cold boot vs. savestate**:
   - A Flycast savestate also holds the memory card as it was when the state was saved. A state saved before the unlocked save existed shows an empty card ("file not found").
   - Boot the disc normally (no savestate) to see the card file on disk.
2. **How NET GAME loads your VMU Frame (`SETTEAMDATA` → `171`)**:
   - Selecting `NET GAME` from the main menu resets the active net frame rather than keeping a previously loaded `CONTINUE` frame in RAM.
   - Inside the Team Room (`ui=49`), press `START` → **騎兵設定** (`ui=50` → `ui=51` → `ui=68`).
   - Entering **騎兵設定** sends `SETTEAMDATA <team> <hex60>` and waits for lobby response `171 <team> <hex60>`. `lobby_probe.py` now handles `SETTEAMDATA` and broadcasts `171`.
   - Inside **騎兵設定** (`ui=68`): open **記 録** → **ロード** → select Card `A-1` → select `001` → **Yes** → **OK** → press `B` → select **設定終了**. Exiting **騎兵設定** triggers `CHANGEUSERDATA` (`170`), updating battle records (e.g. `9999戦 9999勝`) and synchronizing all unlocked equipment with P2 in both Team Room and 3D battle.
