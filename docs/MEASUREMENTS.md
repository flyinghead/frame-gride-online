# Measurements

All results: two Flycast 2.7 windows on one Windows PC, the bridge adding the delay, jitter or loss between the consoles. An automated script played the full flow each time: dial, lobby, team, battle, KO, back to the team room, second battle.

## Delay, jitter, loss

| Added between the consoles | Result |
|---|---|
| 0-50 ms one way | stable |
| 100 ms one way | marginal (sometimes fails at the battle start) |
| 200 ms one way | fails |
| jitter 0-40 ms (uniform) | pass |
| loss 1 / 3 / 5 % | pass (the game's own reliable layer absorbs the drops) |
| 50 ms + jitter 40 ms; 50 ms + jitter 30 ms + loss 2 % | pass |

The jitter and loss rows: 2 runs each, 12 of 12 passed.

**Not measured yet:** a real internet path. The bridge link is TCP, so a lost packet on the internet shows up as a delay spike rather than a drop; how the game takes that is unknown.

## Input lag in the battle

Frames (60 per second) from a button press until the mech data in RAM changes.

| Path | Own screen | Seen on the other console |
|---|---|---|
| Offline (story-mode battle) | 2-8 f | - |
| Network, 0 ms added | 13-17 f (about 220-280 ms) | 12-16 f |
| Network, 50 ms one way | P1 27-29 f, P2 10-16 f | 16-21 f |

The network battle is about 10 frames (~170 ms) slower than offline even with no added delay, and both consoles see a move at nearly the same time (lockstep with buffered input). The buffer very likely follows the round trip the game measures before the battle (about 127 ms with no added delay, mostly the emulated 33.6k modem), but the formula was not confirmed.

Whether this lag is acceptable in real play has not been judged yet.

## Loading

From the team room to the battle takes about 16 s, of which ~10.7 s is the round-trip measurement screen. It is fixed in the game and does not depend on the path delay.
