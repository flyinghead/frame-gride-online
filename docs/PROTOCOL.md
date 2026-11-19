# What the bridge and the lobby speak

Notes from reverse engineering the game's network code and from logs of real sessions on Flycast 2.7. Names in the game code are our own guesses.

## Path of the data

```
Dreamcast (Flycast) ──raw modem bytes over TCP 7654──▶ modem_bridge.py ──UDP 9500/9501 (local)──▶ lobby_probe.py
                                                       │
                                                       └── routes IP between the consoles (battle traffic)
```

With `DCNet = yes`, Flycast does not run its own PPP stack: it sends the emulated modem's byte stream to `DCNetServer` on TCP 7654. `modem_bridge.py --mode ppp` terminates PPP on that stream (`ppp_engine.py`).

## PPP (`ppp_engine.py`)

- HDLC-like framing (RFC 1662) with the FCS-16; frames start and end with `0x7E`.
- **LCP**: accepts MRU, ACCM, magic number, PFC and ACFC. **The console's ACCM must be honored**: control characters it asks to escape are escaped on the way back. Sending them raw made the battle handshake fail now and then.
- **IPCP**: the server offers `192.168.167.1`; the first console gets `192.168.167.2`, the next `.3`, and so on. The console first asks for `0.0.0.0` and gets a NAK with its address.
- **VJ header compression**: with `--vj asymmetric` (default) the server's IPCP request carries the VJ option (the game acks it) and the game's own VJ request is rejected, so the server never sends compressed frames. The bridge has no VJ decompressor, and the game never sent a compressed frame in the captured sessions. See [HANDSHAKE.md](HANDSHAKE.md).
- The game talks to the lobby at the fixed address `172.16.0.21` (built into the game); the bridge turns those UDP packets into local UDP to `127.0.0.1:9500/9501` and back.
- Packets between `192.168.167.x` addresses (console to console) are forwarded inside the bridge, in order. The test options `--p2p-delay-ms`, `--p2p-jitter-ms` and `--p2p-loss-pct` act only on these.

## Lobby (`lobby_probe.py`)

Text commands over UDP, one per datagram, Shift-JIS, padded with NUL bytes:

```
<n> <n> <n> COMMAND [arguments]
```

Replies start with a three-digit code. The ones the game needs:

| Client sends | Server answers | Meaning |
|---|---|---|
| `REQUEST_FILTER` | `1001 <name> 172.16.0.21 9501` | server list (port 9500) |
| `NICK` | `100 <uid> <token> ...` | log in |
| `USER`, `LIST`, `GAMELIST`, `SELECTGAME` | `101`, `109`, `116`, `123` | lobby and game selection |
| `JOIN`, `PART`, `WHO`, `WHOIS` | `102`, `103`, `104`, `106` (+`170`, `123`) | lobby members |
| `TEAMLIST`, `CREATETEAM`, `JOINTEAM`, `LEAVETEAM` | `118`, `120`, `121`, `122` | teams |
| `PRIVMSG`, `TEAMMSG` | `114`/`115`, `131` | chat |
| `CHANGEUSERDATA` | `170 <nick> <hex>` to everyone | player data (mech, records) |
| `SETTEAMDATA` | `171 <team> <hex>` to the team | sent when entering 騎兵設定 in the team room; without the answer the menu hangs |
| `PLAY` | `124 <count> *P1 <ip> P2 <ip>` | start: the list of players and their PPP addresses |
| `KEEPALIVE` | nothing | |

After `124` the consoles talk to each other directly (through the bridge), on TCP port 1979 for the reliable channel and the battle handshake.

## Battle start and timeouts (what to keep in mind)

- Before the battle the game measures the round trip with 40 probes (fixed ~10.7 s screen) and derives its send interval from it.
- The handshake `8500` (master) → `9500` (slave) → `8501` must finish within about 450 game ticks (~15 s), or the slave drops the link.
- A keepalive is queued every 300 ticks (~10 s). These limits are why delay above ~100 ms one way fails.
