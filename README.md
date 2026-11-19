# frame-gride-online

English | [日本語](README.ja.md)

**Unofficial fan project.** Brings back the online 2-player mode ("NET GAME") of the Dreamcast game *FRAME GRIDE* (FromSoftware, 1999, `T34201M`) on the [Flycast](https://github.com/flyinghead/flycast) emulator, with an **unmodified disc** and the **official Flycast 2.7**.

The original game servers are long gone. This project replaces them with a small host-side server written in Python (standard library only):

- `modem_bridge.py` + `ppp_engine.py`: a PPP server for Flycast's DCNet modem connection. It answers the console's dial-up, assigns addresses and routes IP packets between the consoles.
- `lobby_probe.py`: a re-implementation of the game's lobby (UDP 9500/9501): nicknames, lobby list, teams, PLAY.
- `unlock_all.py` + `vmu_tool.py`: optional tools that unlock every part, weapon, stone, squire and material in **your own** save, so new players can skip the grind and go straight to battles.

Nothing in the game or in Flycast is patched. No game data is included or distributed.

> This project is not affiliated with or endorsed by FromSoftware, SEGA or the Flycast authors.

## Status

| What | State |
|---|---|
| Dial-up, lobby, team creation and join, PLAY | Works |
| Network battle to the end, rematch, back to the team room | Works (2 Flycast windows on one PC, automated checks) |
| Tolerance on one PC (emulated) | Stable up to 50 ms one-way delay, 100 ms marginal, 200 ms fails; jitter up to 40 ms and 5 % loss pass |
| Two PCs on one LAN (Windows + macOS) | Both reached the same lobby and stayed connected. **A full match across two PCs has not been played yet.** |
| Over the internet | **Not tested yet** |
| Unlock-all save tool | Works; checked in the story mode and in a NET GAME battle (the other player sees the unlocked mech) |

The network battle has about 10 frames (~170 ms) more input lag than an offline battle, even with no added delay. See [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md).

## Requirements

- Your own copy of *FRAME GRIDE* (Japan, `T34201M`) as a disc image.
- [Flycast 2.7](https://github.com/flyinghead/flycast/releases) on each player's PC.
- Python 3 (tested with 3.14), for the server side only. [uv](https://docs.astral.sh/uv/) is used in the examples; plain `python` works too.

## Quick start (one PC, two Flycast windows)

1. Start the lobby and the bridge (two terminals):

   ```
   uv run python lobby_probe.py
   uv run python modem_bridge.py --mode ppp --vj asymmetric
   ```

2. In each Flycast, set in `emu.cfg` (section `[network]`):

   ```
   DCNet = yes
   DCNetServer = 127.0.0.1
   ```

   For two windows on one PC, give each instance its own data folder, `LocalPort` and `ISPUsername` (for example `flycast_p1` / `flycast_p2`).

3. In the game: title → **NET GAME** → enter a name → dial (A) → server (A) → nickname (A). You are in the lobby.
4. Player 1: START → create a team (A, then A, A, START). Player 2: START → down → A → join (A).
5. Player 1 in the team room: START → PLAY (A). Both consoles enter the battle.

## Two PCs

Run `lobby_probe.py` and `modem_bridge.py` on one PC (the host), with the bridge listening on all interfaces:

```
uv run python modem_bridge.py --mode ppp --vj asymmetric --host 0.0.0.0
```

The other player sets `DCNetServer` to the host's address. Only **TCP 7654** on the host has to be reachable (allow it in the host's firewall). On the internet this means a port forward, or a VPN such as Tailscale. The lobby stays on the host: the bridge forwards the console's lobby packets to it locally.

Path delay counts directly against the game's limits (see the tolerance above), so a nearby host is best.

## Unlocking everything in your save

The card must already hold a save: play the story mode once, enter a name, save. Then, with Flycast closed:

```
uv run python unlock_all.py T34201M_vmu_save_A1.bin unlocked/T34201M_vmu_save_A1.bin
uv run python vmu_tool.py unlocked/T34201M_vmu_save_A1.bin
```

The original card is never overwritten; keep a copy anyway. Put the new card in Flycast's data folder. To use the unlocked mech in NET GAME: in the team room, START → 騎兵設定 → 記 録 → ロード → pick the save → B → 設定終了. Details: [docs/SAVE_FORMAT.md](docs/SAVE_FORMAT.md).

## Bridge options for testing

`modem_bridge.py` can add delay, jitter and loss between the consoles to rehearse a longer path on one PC: `--p2p-delay-ms`, `--p2p-jitter-ms`, `--p2p-loss-pct`, `--p2p-seed`. Both servers write JSON-lines logs next to the scripts (`modem-capture.jsonl` or the `--log` path, `lobby-probe.jsonl`).

## Tests

```
uv run python -m unittest discover
```

Two tests read a real memory card if you point `FG_SAVE_IMAGE` at one; otherwise they are skipped.

## Documents

- [docs/PROTOCOL.md](docs/PROTOCOL.md): what the bridge and the lobby speak.
- [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md): delay, jitter, loss and input-lag results.
- [docs/SAVE_FORMAT.md](docs/SAVE_FORMAT.md): the save file layout and the unlock tool.

## License

MIT, see [LICENSE](LICENSE). The license covers this project's code and documents only, not the game or Flycast.

