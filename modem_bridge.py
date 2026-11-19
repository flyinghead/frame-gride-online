from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path

from ppp_engine import FLAG, PppBridgeSession, PppRouter, decode_ppp_frame, ppp_fcs

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / 'modem-capture.jsonl'
DEFAULT_RAW = BASE_DIR / 'modem-rx.bin'

# Set FG_TRACE_CHUNKS=1 to log the size and arrival time of every TCP chunk received from Flycast.
TRACE_CHUNKS = os.environ.get('FG_TRACE_CHUNKS') == '1'


class HdlcStreamDecoder:
    """Split an async HDLC byte stream into 0x7E-delimited raw frame payloads."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.in_frame = False

    def feed(self, data: bytes) -> tuple[bytes, list[bytes]]:
        pre_flag = bytearray()
        frames: list[bytes] = []
        for b in data:
            if b == FLAG:
                if self.in_frame and self.buf:
                    frames.append(bytes(self.buf))
                    self.buf.clear()
                self.in_frame = True
            elif self.in_frame:
                self.buf.append(b)
            else:
                pre_flag.append(b)
        return bytes(pre_flag), frames


class ModemBridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        mode: str,
        log_path: Path,
        raw_path: Path,
        vj_mode: str,
        p2p_delay_ms: float = 0.0,
        p2p_jitter_ms: float = 0.0,
        p2p_loss_pct: float = 0.0,
        p2p_seed: int | None = None,
    ) -> None:
        self.mode = mode
        self.log_path = log_path
        self.raw_path = raw_path
        self.vj_mode = vj_mode
        self.router = PppRouter(
            p2p_delay_ms=p2p_delay_ms, p2p_jitter_ms=p2p_jitter_ms, p2p_loss_pct=p2p_loss_pct, p2p_seed=p2p_seed
        )
        self._log_lock = threading.Lock()
        self._raw_lock = threading.Lock()
        # Keep both files open for the whole run: reopening them for every log line and every received chunk
        # costs more than the game's per-frame budget on Windows.
        self._log_fp = log_path.open('a', encoding='utf-8')
        self._raw_fp = raw_path.open('ab')
        super().__init__(server_address, ModemHandler)

    def server_close(self) -> None:
        super().server_close()
        for fp in (self._log_fp, self._raw_fp):
            try:
                fp.close()
            except OSError:
                pass


class ModemHandler(socketserver.BaseRequestHandler):
    def _log(self, start_ts: float, entry: dict, peer_ip: str | None = None) -> None:
        # 'ts' is per session; 'wall' lets the two sessions' events be ordered against each other.
        record = {'ts': round(time.monotonic() - start_ts, 4), 'wall': round(time.time(), 4)}
        if peer_ip is not None:
            record['session_ip'] = peer_ip
        record.update(entry)
        line = json.dumps(record, ensure_ascii=False)
        with self.server._log_lock:
            print(line, flush=True)
            self.server._log_fp.write(line + '\n')
            self.server._log_fp.flush()

    def handle(self) -> None:
        start_ts = time.monotonic()
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.settimeout(0.01)
        decoder = HdlcStreamDecoder()
        self._log(start_ts, {'event': 'connect', 'peer': list(self.client_address), 'mode': self.server.mode})

        session: PppBridgeSession | None = None
        peer_ip: str | None = None
        try:
            if self.server.mode == 'ppp':
                peer_ip, udp_bind_host = self.server.router.allocate()
                session = PppBridgeSession(
                    send_bytes=self.request.sendall,
                    log_fn=lambda e: self._log(start_ts, e, peer_ip=peer_ip),
                    peer_ip=peer_ip,
                    vj_mode=self.server.vj_mode,
                    udp_bind_host=udp_bind_host,
                    router=self.server.router,
                )
                self._log(
                    start_ts,
                    {'event': 'session_allocated', 'peer_ip': peer_ip, 'udp_bind_host': udp_bind_host},
                    peer_ip=peer_ip,
                )

            while True:
                if session is not None:
                    session.poll_udp_replies()
                try:
                    chunk = self.request.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break

                with self.server._raw_lock:
                    self.server._raw_fp.write(chunk)
                    self.server._raw_fp.flush()

                if TRACE_CHUNKS and self.server.mode == 'ppp':
                    self._log(start_ts, {'event': 'rx_chunk_len', 'len': len(chunk)}, peer_ip=peer_ip)

                if self.server.mode == 'capture':
                    self._log(
                        start_ts,
                        {
                            'event': 'rx_chunk',
                            'len': len(chunk),
                            'hex': chunk.hex(),
                            'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk),
                        },
                        peer_ip=peer_ip,
                    )

                pre_flag, frames = decoder.feed(chunk)
                if pre_flag:
                    self._log(
                        start_ts,
                        {
                            'event': 'rx_pre_flag',
                            'hex': pre_flag.hex(),
                            'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in pre_flag),
                        },
                        peer_ip=peer_ip,
                    )
                for raw_frame in frames:
                    if session is not None:
                        session.handle_frame(raw_frame)
                    else:
                        info = decode_ppp_frame(raw_frame)
                        info.pop('payload', None)
                        self._log(start_ts, {'event': 'rx_ppp_frame', **info}, peer_ip=peer_ip)
        except OSError as exc:
            self._log(start_ts, {'event': 'error', 'detail': str(exc)}, peer_ip=peer_ip)
        finally:
            if session is not None:
                self.server.router.unregister(session)
                session.close()
            elif peer_ip is not None:
                self.server.router.release(peer_ip)
            self._log(start_ts, {'event': 'disconnect'}, peer_ip=peer_ip)


def main() -> None:
    parser = argparse.ArgumentParser(description='Flycast DCNet raw modem bridge')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=7654)
    parser.add_argument('--mode', choices=('capture', 'ppp'), default='capture')
    parser.add_argument('--vj', choices=('accept', 'reject', 'asymmetric'), default='asymmetric')
    parser.add_argument('--log', type=Path, default=DEFAULT_LOG)
    parser.add_argument('--bin', type=Path, default=DEFAULT_RAW)
    parser.add_argument(
        '--p2p-delay-ms',
        type=float,
        default=float(os.environ.get('FG_P2P_DELAY_MS', '0')),
        help='one-way delay added to every console-to-console frame (default: $FG_P2P_DELAY_MS or 0)',
    )
    parser.add_argument(
        '--p2p-jitter-ms',
        type=float,
        default=float(os.environ.get('FG_P2P_JITTER_MS', '0')),
        help='extra random delay, uniform in [0, N] ms, per console-to-console frame (default: $FG_P2P_JITTER_MS or 0)',
    )
    parser.add_argument(
        '--p2p-loss-pct',
        type=float,
        default=float(os.environ.get('FG_P2P_LOSS_PCT', '0')),
        help='percent of console-to-console frames dropped (default: $FG_P2P_LOSS_PCT or 0)',
    )
    parser.add_argument(
        '--p2p-seed',
        type=int,
        default=int(os.environ['FG_P2P_SEED']) if 'FG_P2P_SEED' in os.environ else None,
        help='seed for jitter and loss, so a run can be repeated (default: $FG_P2P_SEED or random)',
    )
    args = parser.parse_args()

    args.log.write_text('', encoding='utf-8')
    args.bin.write_bytes(b'')
    with ModemBridgeServer(
        (args.host, args.port), args.mode, args.log, args.bin, args.vj,
        p2p_delay_ms=args.p2p_delay_ms, p2p_jitter_ms=args.p2p_jitter_ms,
        p2p_loss_pct=args.p2p_loss_pct, p2p_seed=args.p2p_seed,
    ) as srv:
        print(
            json.dumps(
                {
                    'listening': [args.host, args.port],
                    'mode': args.mode,
                    'vj': args.vj,
                    'p2p_delay_ms': args.p2p_delay_ms,
                    'p2p_jitter_ms': args.p2p_jitter_ms,
                    'p2p_loss_pct': args.p2p_loss_pct,
                    'p2p_seed': args.p2p_seed,
                }
            ),
            flush=True,
        )
        srv.serve_forever()


__all__ = ['FLAG', 'HdlcStreamDecoder', 'decode_ppp_frame', 'ppp_fcs']

if __name__ == '__main__':
    main()
