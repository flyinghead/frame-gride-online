# PPP handshake of FRAME GRIDE (T34201M)

The exact PPP negotiation that works between Flycast 2.7 (`DCNet = yes`) running the unmodified disc and `modem_bridge.py --mode ppp --vj asymmetric` (code: `ppp_engine.py`). It was captured from one real session; the bytes below are copied from the bridge's JSON-lines log, not reconstructed.

Everything here is what the game **does** and what this bridge **answers**. What a stock `pppd` would do is not tested; those points are marked as untested.

## How to read the table

- Payloads only: the bytes after the PPP protocol field and before the FCS. Protocols: LCP `0xC021`, PAP `0xC023`, IPCP `0x8021`.
- LCP / IPCP / PAP packets start with `code id length(2 bytes)`. Codes: 1 Configure-Request, 2 Configure-Ack, 3 Configure-Nak, 4 Configure-Reject. For PAP: 1 Authenticate-Request, 2 Authenticate-Ack.
- `t` is seconds since the game's modem connected to the bridge.

## The sequence

| t (s) | From | Packet | Payload (hex) |
|---:|---|---|---|
| 3.129 | game | LCP Configure-Request, id 0x40 | `01 40 0012 | 01 04 0200 | 07 02 | 08 02 | 02 06 00000000` |
| 3.129 | server | LCP Configure-Ack, id 0x40 | the same bytes with code 2 |
| 3.129 | server | LCP Configure-Request, id 1 | `01 01 000a | 02 06 00000000` |
| 3.268 | game | LCP Configure-Ack, id 1 | `02 01 000a | 02 06 00000000` |
| | | **LCP is open** | |
| 6.131 | game | **PAP Authenticate-Request**, id 0x41 | `01 41 001c | 0a "framegride" | 0c "fromsoftware"` |
| 6.131 | server | PAP Authenticate-Ack | `02 41 0007 | 02 "OK"` |
| 6.131 | server | IPCP Configure-Request, id 2 | `01 02 0010 | 02 06 002d 0f 00 | 03 06 c0a8a701` |
| 6.199 | game | IPCP Configure-Ack, id 2 | `02 02 0010 | 02 06 002d 0f 00 | 03 06 c0a8a701` |
| 6.220 | game | IPCP Configure-Request, id 0x42 | `01 42 0010 | 02 06 002d 0f 00 | 03 06 00000000` |
| 6.220 | server | IPCP Configure-Reject, id 0x42 | `04 42 000a | 02 06 002d 0f 00` |
| 6.267 | game | IPCP Configure-Request, id 0x43 | `01 43 000a | 03 06 00000000` |
| 6.267 | server | IPCP Configure-Nak, id 0x43 | `03 43 000a | 03 06 c0a8a702` |
| 6.289 | game | IPCP Configure-Request, id 0x44 | `01 44 000a | 03 06 c0a8a702` |
| 6.289 | server | IPCP Configure-Ack, id 0x44 | `02 44 000a | 03 06 c0a8a702` |
| | | **IPCP is open** (game 192.168.167.2, server 192.168.167.1) | |

(The `|` marks only separate the header from the options; they are not part of the packet.)

## What the options mean

- **Game LCP options**: MRU 512, protocol-field compression, address/control-field compression, ACCM `0x00000000`. It sends **no Magic-Number and no Authentication-Protocol option**.
- **Server LCP options sent**: ACCM `0x00000000` only. Nothing else has been tried (see "Not tested").
- **PAP**: the game sends it by itself, about 2.9 s after LCP opened, although the server never asked for authentication in LCP. Peer-id `framegride`, password `fromsoftware` (they are built into the game; the bridge accepts any). **The game sends no IPCP packet until it has the PAP Authenticate-Ack.**
- **VJ option** `02 06 00 2d 0f 00`: protocol `0x002d` (Van Jacobson), max-slot-id 15, comp-slot-id 0. In my decompilation notes the game's IPCP code compares against exactly these six bytes. The server offers it in its own request and the game acks it; the game's own VJ request is rejected, so the server never sends VJ-compressed packets (`--vj asymmetric`). The bridge has no VJ decompressor, and in the captured sessions the game never sent a VJ-compressed frame (no packet with protocol `0x002d` or `0x002f` was logged), so VJ is not actually used in either direction.
- **Address**: the game asks for `0.0.0.0` and is given `192.168.167.2` by a Configure-Nak.
- **ACCM after LCP opens**: the bridge escapes only `0x7D` and `0x7E` when sending, because the game asked for ACCM 0. Ignoring this and escaping every control character did not break the dial-up, but it made frames larger and slowed the battle start enough to fail it sometimes.

## What a server needs to do (as observed)

1. Acknowledge the game's LCP request as is.
2. Answer the game's **unsolicited PAP** request with an Authenticate-Ack, and only then expect IPCP from the game.
3. Offer or accept the VJ option with exactly the six bytes above, or reject it as in the table.
4. Give the game an address with a Configure-Nak when it asks for `0.0.0.0`.

## Not tested

- A stock `pppd`. A guess, not a finding: `pppd` ignores a PAP request unless it is set up to require PAP, which would leave the game waiting for the Ack with nothing wrong on the wire.
- An LCP Configure-Request from the server that contains a Magic-Number, an MRU or an Authentication-Protocol option.
- An IPCP Configure-Request from the server **before** the PAP Ack (the bridge sends it right after the Ack).
- A VJ option with other max-slot or compression-flag values.
- The game when the server rejects VJ entirely (`--vj reject` exists in the code and its unit tests, but the full battle was run with `asymmetric`).

## Capturing your own log

`modem_bridge.py --mode ppp --vj asymmetric --log ppp.jsonl` writes one JSON object per line. The handshake is in the events `rx_lcp`, `rx_pap`, `rx_ipcp` (from the game) and `tx_ppp` with the notes `lcp_ack`, `lcp_cr`, `pap_ack`, `ipcp_cr`, `ipcp_rej`, `ipcp_nak`, `ipcp_ack` (from the server), each with the payload in `hex`.
