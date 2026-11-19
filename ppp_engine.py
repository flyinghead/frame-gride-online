from __future__ import annotations

import ipaddress
import queue
import random
import socket
import struct
import threading
import time
from typing import Callable

FLAG = 0x7E
ESCAPE = 0x7D
GOOD_FCS = 0xF0B8

PROTO_IP = 0x0021
PROTO_VJ_COMP = 0x002D
PROTO_VJ_UNCOMP = 0x002F
PROTO_IPCP = 0x8021
PROTO_LCP = 0xC021
PROTO_PAP = 0xC023

CP_CONF_REQ = 1
CP_CONF_ACK = 2
CP_CONF_NAK = 3
CP_CONF_REJ = 4
CP_TERM_REQ = 5
CP_TERM_ACK = 6
CP_CODE_REJ = 7
CP_PROTO_REJ = 8
CP_ECHO_REQ = 9
CP_ECHO_REP = 10

PROTO_NAMES = {
    PROTO_IP: 'IP',
    PROTO_VJ_COMP: 'VJ_COMP_TCP',
    PROTO_VJ_UNCOMP: 'VJ_UNCOMP_TCP',
    PROTO_IPCP: 'IPCP',
    PROTO_LCP: 'LCP',
    PROTO_PAP: 'PAP',
}


def ppp_fcs(data: bytes) -> int:
    """Compute PPP RFC 1662 16-bit FCS over unescaped frame bytes."""
    fcs = 0xFFFF
    for b in data:
        fcs ^= b
        for _ in range(8):
            if fcs & 1:
                fcs = (fcs >> 1) ^ 0x8408
            else:
                fcs >>= 1
    return fcs


def internet_checksum(data: bytes) -> int:
    """Compute standard RFC 1071 16-bit one's complement checksum."""
    if len(data) & 1:
        data = data + b'\x00'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def encode_ppp_frame(proto: int, payload: bytes, accm: int = 0xFFFFFFFF) -> bytes:
    """Build HDLC-framed PPP bytes with both leading and trailing 0x7E flags."""
    body = bytes([0xFF, 0x03]) + struct.pack('!H', proto) + payload
    fcs = ppp_fcs(body) ^ 0xFFFF
    raw = body + struct.pack('<H', fcs)
    out = bytearray([FLAG])
    for b in raw:
        must_escape = b in (FLAG, ESCAPE) or (b < 0x20 and ((accm >> b) & 1))
        if must_escape:
            out.append(ESCAPE)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def decode_ppp_frame(raw_escaped: bytes) -> dict:
    """Unescape and parse one PPP frame (supports optional FF 03 and 1-byte PFC)."""
    unescaped = bytearray()
    esc = False
    for b in raw_escaped:
        if esc:
            unescaped.append(b ^ 0x20)
            esc = False
        elif b == ESCAPE:
            esc = True
        else:
            unescaped.append(b)

    data = bytes(unescaped)
    info: dict = {
        'raw_len': len(raw_escaped),
        'unescaped_hex': data.hex(),
        'fcs_ok': False,
    }
    if esc or len(data) < 4:
        info['error'] = 'short_or_trailing_escape'
        return info

    info['fcs_ok'] = ppp_fcs(data) == GOOD_FCS
    body = data[:-2]

    idx = 0
    if len(body) >= 2 and body[0] == 0xFF and body[1] == 0x03:
        info['hdlc_addr_ctrl'] = True
        idx = 2
    else:
        info['hdlc_addr_ctrl'] = False

    if idx >= len(body):
        info['error'] = 'missing_proto'
        return info

    if body[idx] & 1:
        proto = body[idx]
        idx += 1
    elif idx + 1 < len(body):
        proto = struct.unpack('!H', body[idx : idx + 2])[0]
        idx += 2
    else:
        info['error'] = 'truncated_proto'
        return info

    payload = body[idx:]
    info['proto'] = f'0x{proto:04x}'
    info['proto_num'] = proto
    info['proto_name'] = PROTO_NAMES.get(proto, f'0x{proto:04x}')
    info['payload'] = payload

    if proto in (PROTO_LCP, PROTO_IPCP) and len(payload) >= 4:
        info['cp'] = parse_cp_packet(proto, payload)
    return info


def parse_cp_options(opt_bytes: bytes) -> list[dict]:
    """Parse TLV options inside an LCP or IPCP packet."""
    options = []
    pos = 0
    while pos + 2 <= len(opt_bytes):
        opt_type = opt_bytes[pos]
        opt_len = opt_bytes[pos + 1]
        if opt_len < 2 or pos + opt_len > len(opt_bytes):
            options.append({'type': opt_type, 'malformed_hex': opt_bytes[pos:].hex()})
            break
        val = opt_bytes[pos + 2 : pos + opt_len]
        item: dict = {'type': opt_type, 'raw': opt_bytes[pos : pos + opt_len], 'val': val}
        options.append(item)
        pos += opt_len
    return options


def parse_cp_packet(proto: int, payload: bytes) -> dict:
    """Parse LCP / IPCP / PAP header + payload."""
    code, pkt_id, length = struct.unpack('!BBH', payload[:4])
    data = payload[4:length]
    res: dict = {
        'code': code,
        'id': pkt_id,
        'length': length,
        'data': data,
    }
    if code in (CP_CONF_REQ, CP_CONF_ACK, CP_CONF_NAK, CP_CONF_REJ):
        res['options'] = parse_cp_options(data)
    elif code == CP_ECHO_REQ and len(data) >= 4:
        res['magic'] = data[:4]
        res['echo_data'] = data[4:]
    return res


def build_cp_packet(code: int, pkt_id: int, data: bytes) -> bytes:
    """Build an LCP/IPCP/PAP packet with 4-byte code/id/length header."""
    return struct.pack('!BBH', code, pkt_id & 0xFF, 4 + len(data)) + data


def build_ipv4_udp_packet(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, udp_payload: bytes, ip_id: int = 1
) -> bytes:
    """Construct a complete IPv4 + UDP packet with valid header and UDP checksums."""
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed
    udp_len = 8 + len(udp_payload)
    udp_hdr_zero = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    pseudo = src_b + dst_b + struct.pack('!BBH', 0, 17, udp_len)
    udp_csum = internet_checksum(pseudo + udp_hdr_zero + udp_payload)
    if udp_csum == 0:
        udp_csum = 0xFFFF
    udp_seg = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_csum) + udp_payload

    total_len = 20 + len(udp_seg)
    ip_hdr_zero = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        17,
        0,
        src_b,
        dst_b,
    )
    ip_csum = internet_checksum(ip_hdr_zero)
    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        17,
        ip_csum,
        src_b,
        dst_b,
    )
    return ip_hdr + udp_seg


def parse_ipv4_packet(pkt: bytes) -> dict | None:
    """Parse an IPv4 packet and extract UDP, TCP, or ICMP fields when present."""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    total_len = struct.unpack('!H', pkt[2:4])[0]
    if total_len < ihl or total_len > len(pkt):
        total_len = len(pkt)
    proto = pkt[9]
    src_ip = str(ipaddress.IPv4Address(pkt[12:16]))
    dst_ip = str(ipaddress.IPv4Address(pkt[16:20]))
    l4 = pkt[ihl:total_len]
    out: dict = {'proto': proto, 'src_ip': src_ip, 'dst_ip': dst_ip, 'l4': l4}
    if proto == 17 and len(l4) >= 8:
        sport, dport, ulen, _ = struct.unpack('!HHHH', l4[:8])
        out['src_port'] = sport
        out['dst_port'] = dport
        out['udp_payload'] = l4[8:ulen] if ulen >= 8 else l4[8:]
    elif proto == 6 and len(l4) >= 4:
        sport, dport = struct.unpack('!HH', l4[:4])
        out['src_port'] = sport
        out['dst_port'] = dport
    return out


class PppRouter:
    """Thread-safe registry for multi-session PPP IP allocation and L3 IPv4 forwarding."""

    def __init__(
        self,
        subnet_prefix: str = '192.168.167',
        start_octet: int = 2,
        max_octet: int = 254,
        p2p_delay_ms: float = 0.0,
        p2p_jitter_ms: float = 0.0,
        p2p_loss_pct: float = 0.0,
        p2p_seed: int | None = None,
    ) -> None:
        self._lock = threading.Lock()
        # One-way delay added to every console-to-console frame, to rehearse a longer path (RTT grows by twice this).
        self.p2p_delay_s = max(0.0, p2p_delay_ms) / 1000.0
        # Extra random delay per frame, uniform in [0, jitter]; frames still leave in arrival order.
        self.p2p_jitter_s = max(0.0, p2p_jitter_ms) / 1000.0
        # Chance (0-100) that a console-to-console frame is dropped, as on a lossy path.
        self.p2p_loss = min(100.0, max(0.0, p2p_loss_pct)) / 100.0
        self._rng = random.Random(p2p_seed)
        self.subnet_prefix = subnet_prefix
        self.start_octet = start_octet
        self.max_octet = max_octet
        self._sessions: dict[str, PppBridgeSession | None] = {}

    def bind_host_for_ip(self, peer_ip: str) -> str:
        """Map a PPP peer IP in the managed subnet to a distinct 127.0.0.<octet> loopback bind host."""
        prefix = f'{self.subnet_prefix}.'
        if peer_ip.startswith(prefix):
            return f'127.0.0.{peer_ip[len(prefix):]}'
        return '127.0.0.1'

    def allocate(self) -> tuple[str, str]:
        """Atomically reserve the lowest free PPP peer IP and its loopback UDP bind host."""
        with self._lock:
            for octet in range(self.start_octet, self.max_octet + 1):
                peer_ip = f'{self.subnet_prefix}.{octet}'
                if peer_ip not in self._sessions:
                    self._sessions[peer_ip] = None
                    return peer_ip, f'127.0.0.{octet}'
        raise RuntimeError('No available PPP IP addresses in pool')

    def release(self, peer_ip: str) -> None:
        """Release an unattached IP reservation."""
        with self._lock:
            if peer_ip in self._sessions and self._sessions[peer_ip] is None:
                del self._sessions[peer_ip]

    def register(self, session: PppBridgeSession) -> None:
        """Bind a live PppBridgeSession to its peer IP in the routing table."""
        with self._lock:
            self._sessions[session.peer_ip] = session

    def unregister(self, session: PppBridgeSession) -> None:
        """Remove a session from the routing table and free its peer IP."""
        with self._lock:
            if self._sessions.get(session.peer_ip) is session:
                del self._sessions[session.peer_ip]

    def get_session(self, dst_ip: str) -> PppBridgeSession | None:
        """Return the active session owning dst_ip, if any."""
        with self._lock:
            return self._sessions.get(dst_ip)

    def forward_ipv4(self, dst_ip: str, pkt: bytes) -> bool:
        """Forward a raw IPv4 packet to the registered session for dst_ip, if active."""
        target = self.get_session(dst_ip)
        if target is None:
            return False
        with self._lock:
            dropped = self.p2p_loss > 0 and self._rng.random() < self.p2p_loss
            delay_s = self.p2p_delay_s + (self._rng.uniform(0.0, self.p2p_jitter_s) if self.p2p_jitter_s > 0 else 0.0)
        if dropped:
            target.log_fn({'event': 'p2p_drop', 'len': len(pkt)})
            return True  # the sender sees a normal send; the frame is lost on the path
        # Deliver outside self._lock to avoid lock inversion with target._tx_lock
        if delay_s > 0:
            return target.deliver_ipv4_later(pkt, delay_s)
        return target.deliver_ipv4(pkt)


class PppBridgeSession:
    """Drives LCP, optional PAP, IPCP (with VJ support/reject/asymmetric), and IPv4 forwarding."""

    def __init__(
        self,
        send_bytes: Callable[[bytes], None],
        log_fn: Callable[[dict], None],
        peer_ip: str | None = None,
        server_ip: str = '192.168.167.1',
        vj_mode: str = 'accept',
        udp_target_host: str = '127.0.0.1',
        udp_bind_host: str | None = None,
        router: PppRouter | None = None,
    ) -> None:
        if vj_mode not in ('accept', 'reject', 'asymmetric'):
            raise ValueError(f'Unsupported vj_mode: {vj_mode}')

        self.send_bytes = send_bytes
        self.log_fn = log_fn
        self.server_ip = server_ip
        self.vj_mode = vj_mode
        self.udp_target_host = udp_target_host
        self.router = router
        self._tx_lock = threading.RLock()

        if router is not None and peer_ip is None:
            allocated_ip, allocated_bind = router.allocate()
            self.peer_ip = allocated_ip
            self.udp_bind_host = udp_bind_host or allocated_bind
        else:
            self.peer_ip = peer_ip or '192.168.167.2'
            if udp_bind_host is not None:
                self.udp_bind_host = udp_bind_host
            elif router is not None:
                self.udp_bind_host = router.bind_host_for_ip(self.peer_ip)
            else:
                self.udp_bind_host = '127.0.0.1'

        self.lcp_server_id = 1
        self.ipcp_server_id = 1
        self.ip_id = 1
        # Control characters the Dreamcast asked us to escape (its LCP ACCM option). RFC 1662 maps all of them
        # until LCP is open, then only the ones the peer named; the game requests 0, so only 0x7D/0x7E stay mapped.
        self.tx_accm = 0xFFFFFFFF
        self._peer_accm = 0xFFFFFFFF
        self.lcp_peer_acked = False
        self.lcp_server_acked = False
        self.lcp_opened = False
        self.ipcp_started = False
        self.ipcp_peer_acked = False
        self.ipcp_server_acked = False

        # Server LCP options offered to Dreamcast: ACCM = 0x00000000
        self.server_lcp_options = [b'\x02\x06\x00\x00\x00\x00']
        # Map (src_ip, src_port, dst_ip, dst_port) -> local UDP socket
        self.udp_sockets: dict[tuple[str, int, str, int], socket.socket] = {}
        self.closed = False
        # Frames waiting out the router's p2p delay; one worker per session keeps their order.
        self._delay_q: queue.Queue | None = None
        self._last_due = 0.0
        self._delay_lock = threading.Lock()

        if self.router is not None:
            self.router.register(self)

    def _tx_ppp(self, proto: int, payload: bytes, note: str) -> None:
        raw = encode_ppp_frame(proto, payload, self.tx_accm)
        with self._tx_lock:
            self.log_fn({'event': 'tx_ppp', 'proto': f'0x{proto:04x}', 'note': note, 'hex': payload.hex()})
            self.send_bytes(raw)

    def deliver_ipv4(self, pkt: bytes) -> bool:
        """Thread-safe delivery of a raw IPv4 packet from a peer session as PROTO_IP."""
        with self._tx_lock:
            if self.closed:
                return False
            try:
                self._tx_ppp(PROTO_IP, pkt, 'p2p_ipv4')
            except OSError as exc:
                self.log_fn({'event': 'forward_p2p_error', 'detail': str(exc)})
                return False
            return True

    def deliver_ipv4_later(self, pkt: bytes, delay_s: float) -> bool:
        """Queue a peer's IPv4 packet for delivery `delay_s` from now, in arrival order."""
        with self._tx_lock:
            if self.closed:
                return False
        with self._delay_lock:
            if self._delay_q is None:
                self._delay_q = queue.Queue()
                threading.Thread(target=self._run_delay_worker, args=(self._delay_q,), daemon=True).start()
            # Never due before the previous frame, so jitter delays the ones behind it instead of reordering them.
            due = max(time.monotonic() + delay_s, self._last_due)
            self._last_due = due
            self._delay_q.put((due, pkt))
        return True

    def _run_delay_worker(self, delay_q: queue.Queue) -> None:
        while True:
            item = delay_q.get()
            if item is None:
                return
            due, pkt = item
            wait = due - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self.deliver_ipv4(pkt)

    def _send_server_lcp_cr(self) -> None:
        data = b''.join(self.server_lcp_options)
        self._tx_ppp(PROTO_LCP, build_cp_packet(CP_CONF_REQ, self.lcp_server_id, data), 'lcp_cr')

    def _send_server_ipcp_cr(self) -> None:
        opts = bytearray()
        if self.vj_mode in ('accept', 'asymmetric'):
            # FUN_8c0ba5bc checks for option 02 06 00 2d 0f 00 when VJ enabled
            opts += b'\x02\x06\x00\x2d\x0f\x00'
        opts += b'\x03\x06' + ipaddress.IPv4Address(self.server_ip).packed
        self._tx_ppp(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, self.ipcp_server_id, bytes(opts)), 'ipcp_cr')

    def _maybe_start_ipcp(self) -> None:
        if self.lcp_peer_acked and self.lcp_server_acked and not self.lcp_opened:
            self.lcp_opened = True
            self.tx_accm = self._peer_accm
            self.log_fn({'event': 'lcp_open', 'tx_accm': f'0x{self.tx_accm:08x}'})

    def _start_ipcp_if_needed(self) -> None:
        if not self.ipcp_started:
            self.ipcp_started = True
            self._send_server_ipcp_cr()

    def handle_frame(self, raw_escaped: bytes) -> None:
        info = decode_ppp_frame(raw_escaped)
        if not info.get('fcs_ok') or 'proto_num' not in info:
            self.log_fn({'event': 'rx_bad_frame', 'info': {k: v for k, v in info.items() if k != 'payload'}})
            return

        proto = info['proto_num']
        payload: bytes = info['payload']
        if proto == PROTO_LCP:
            self._handle_lcp(payload)
        elif proto == PROTO_PAP:
            self._handle_pap(payload)
        elif proto == PROTO_IPCP:
            self._handle_ipcp(payload)
        elif proto == PROTO_IP:
            self._handle_ipv4(payload)
        else:
            self.log_fn({'event': 'rx_other_proto', 'proto': f'0x{proto:04x}', 'len': len(payload)})

    def _handle_lcp(self, payload: bytes) -> None:
        cp = parse_cp_packet(PROTO_LCP, payload)
        code, pkt_id = cp['code'], cp['id']
        self.log_fn({'event': 'rx_lcp', 'code': code, 'id': pkt_id, 'hex': payload.hex()})

        if code == CP_CONF_REQ:
            # Accept MRU(1), ACCM(2), Magic(5), PFC(7), ACFC(8); reject anything unexpected
            rej = bytearray()
            for opt in cp.get('options', []):
                if opt['type'] not in (1, 2, 5, 7, 8):
                    rej += opt['raw']
            if rej:
                self._tx_ppp(PROTO_LCP, build_cp_packet(CP_CONF_REJ, pkt_id, bytes(rej)), 'lcp_rej')
                return
            self._tx_ppp(PROTO_LCP, build_cp_packet(CP_CONF_ACK, pkt_id, cp['data']), 'lcp_ack')
            # No ACCM option means the RFC default: the peer needs every control character escaped.
            self._peer_accm = 0xFFFFFFFF
            for opt in cp.get('options', []):
                if opt['type'] == 2 and len(opt['val']) == 4:
                    self._peer_accm = struct.unpack('!I', opt['val'])[0]
            if self.lcp_opened:
                self.tx_accm = self._peer_accm
            self.lcp_peer_acked = True
            if not self.lcp_server_acked:
                self._send_server_lcp_cr()
            self._maybe_start_ipcp()
        elif code == CP_CONF_ACK:
            self.lcp_server_acked = True
            self._maybe_start_ipcp()
        elif code == CP_CONF_REJ:
            rej_types = {opt['type'] for opt in cp.get('options', [])}
            self.server_lcp_options = [o for o in self.server_lcp_options if o[0] not in rej_types]
            self.lcp_server_id = (self.lcp_server_id % 255) + 1
            self._send_server_lcp_cr()
        elif code == CP_CONF_NAK:
            self.lcp_server_id = (self.lcp_server_id % 255) + 1
            self._send_server_lcp_cr()
        elif code == CP_TERM_REQ:
            self._tx_ppp(PROTO_LCP, build_cp_packet(CP_TERM_ACK, pkt_id, b''), 'lcp_term_ack')
        elif code == CP_ECHO_REQ:
            reply_data = b'\x00\x00\x00\x00' + cp.get('echo_data', b'')
            self._tx_ppp(PROTO_LCP, build_cp_packet(CP_ECHO_REP, pkt_id, reply_data), 'lcp_echo_rep')

    def _handle_pap(self, payload: bytes) -> None:
        cp = parse_cp_packet(PROTO_PAP, payload)
        self.log_fn({'event': 'rx_pap', 'code': cp['code'], 'id': cp['id'], 'hex': payload.hex()})
        if cp['code'] == CP_CONF_REQ:
            msg = b'\x02OK'
            self._tx_ppp(PROTO_PAP, build_cp_packet(CP_CONF_ACK, cp['id'], msg), 'pap_ack')
            self.ipcp_started = True
            self.ipcp_peer_acked = False
            self.ipcp_server_acked = False
            self.ipcp_server_id = (self.ipcp_server_id % 255) + 1
            self._send_server_ipcp_cr()

    def _handle_ipcp(self, payload: bytes) -> None:
        cp = parse_cp_packet(PROTO_IPCP, payload)
        code, pkt_id = cp['code'], cp['id']
        self.log_fn({'event': 'rx_ipcp', 'code': code, 'id': pkt_id, 'hex': payload.hex()})

        if not self.ipcp_started:
            self.ipcp_started = True
            self._send_server_ipcp_cr()

        if code == CP_CONF_REQ:
            rej = bytearray()
            nak = bytearray()
            for opt in cp.get('options', []):
                otype = opt['type']
                if otype == 2:
                    if self.vj_mode in ('reject', 'asymmetric'):
                        rej += opt['raw']
                    elif opt['val'] != b'\x00\x2d\x0f\x00':
                        nak += b'\x02\x06\x00\x2d\x0f\x00'
                elif otype == 3:
                    wanted = ipaddress.IPv4Address(self.peer_ip).packed
                    if opt['val'] != wanted:
                        nak += b'\x03\x06' + wanted
                elif otype in (129, 131):  # Primary / Secondary DNS
                    dns = ipaddress.IPv4Address(self.server_ip).packed
                    if opt['val'] != dns:
                        nak += bytes([otype, 6]) + dns
                else:
                    rej += opt['raw']

            if rej:
                self._tx_ppp(PROTO_IPCP, build_cp_packet(CP_CONF_REJ, pkt_id, bytes(rej)), 'ipcp_rej')
            elif nak:
                self._tx_ppp(PROTO_IPCP, build_cp_packet(CP_CONF_NAK, pkt_id, bytes(nak)), 'ipcp_nak')
            else:
                was_peer_acked = self.ipcp_peer_acked
                self._tx_ppp(PROTO_IPCP, build_cp_packet(CP_CONF_ACK, pkt_id, cp['data']), 'ipcp_ack')
                self.ipcp_peer_acked = True
                if not self.ipcp_server_acked or was_peer_acked:
                    # Resend server CR if game hadn't ACKed post-PAP or is retrying in Ack-Rcvd
                    self.ipcp_server_acked = False
                    self.ipcp_server_id = (self.ipcp_server_id % 255) + 1
                    self._send_server_ipcp_cr()
                else:
                    self.log_fn({'event': 'ipcp_open', 'peer_ip': self.peer_ip, 'server_ip': self.server_ip})
        elif code == CP_CONF_ACK:
            self.ipcp_server_acked = True
            if self.ipcp_peer_acked:
                self.log_fn({'event': 'ipcp_open', 'peer_ip': self.peer_ip, 'server_ip': self.server_ip})
        elif code == CP_CONF_NAK:
            self.ipcp_server_id = (self.ipcp_server_id % 255) + 1
            self._send_server_ipcp_cr()
        elif code == CP_CONF_REJ:
            rej_types = {opt['type'] for opt in cp.get('options', [])}
            if 2 in rej_types:
                self.vj_mode = 'reject'
            self.ipcp_server_id = (self.ipcp_server_id % 255) + 1
            self._send_server_ipcp_cr()

    def _get_udp_socket(self, flow: tuple[str, int, str, int]) -> socket.socket:
        sock = self.udp_sockets.get(flow)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.bind((self.udp_bind_host, 0))
            self.udp_sockets[flow] = sock
        return sock

    def _handle_ipv4(self, pkt: bytes) -> None:
        parsed = parse_ipv4_packet(pkt)
        if not parsed:
            self.log_fn({'event': 'rx_ip_invalid', 'hex': pkt.hex()})
            return
        if self.router is not None and self.router.forward_ipv4(parsed['dst_ip'], pkt):
            self.log_fn(
                {
                    'event': 'forward_p2p',
                    'ip_proto': parsed['proto'],
                    'src': parsed['src_ip'],
                    'dst': parsed['dst_ip'],
                    'len': len(pkt),
                }
            )
            return
        if parsed['proto'] == 17 and 'udp_payload' in parsed:
            flow = (parsed['src_ip'], parsed['src_port'], parsed['dst_ip'], parsed['dst_port'])
            payload: bytes = parsed['udp_payload']
            self.log_fn(
                {
                    'event': 'rx_udp',
                    'src': f"{flow[0]}:{flow[1]}",
                    'dst': f"{flow[2]}:{flow[3]}",
                    'len': len(payload),
                    'hex': payload.hex(),
                    'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload),
                }
            )
            sock = self._get_udp_socket(flow)
            sock.sendto(payload, (self.udp_target_host, flow[3]))
        elif parsed['proto'] == 1 and len(parsed['l4']) >= 8 and parsed['l4'][0] == 8:
            # Reply to ICMP Echo-Request so ping checks don't stall
            icmp = bytearray(parsed['l4'])
            icmp[0] = 0
            icmp[2:4] = b'\x00\x00'
            csum = internet_checksum(bytes(icmp))
            icmp[2:4] = struct.pack('!H', csum)
            self._send_raw_ipv4(parsed['dst_ip'], parsed['src_ip'], 1, bytes(icmp))
            self.log_fn({'event': 'tx_icmp_echo_reply', 'dst': parsed['src_ip']})
        else:
            self.log_fn(
                {
                    'event': 'rx_ip_other',
                    'ip_proto': parsed['proto'],
                    'src': parsed['src_ip'],
                    'dst': parsed['dst_ip'],
                    'len': len(pkt),
                }
            )

    def _send_raw_ipv4(self, src_ip: str, dst_ip: str, ip_proto: int, l4: bytes) -> None:
        src_b = ipaddress.IPv4Address(src_ip).packed
        dst_b = ipaddress.IPv4Address(dst_ip).packed
        total_len = 20 + len(l4)
        with self._tx_lock:
            self.ip_id = (self.ip_id + 1) & 0xFFFF
            ip_id = self.ip_id
            ip_zero = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ip_id, 0x4000, 64, ip_proto, 0, src_b, dst_b)
            ip_csum = internet_checksum(ip_zero)
            ip_hdr = struct.pack(
                '!BBHHHBBH4s4s', 0x45, 0, total_len, ip_id, 0x4000, 64, ip_proto, ip_csum, src_b, dst_b
            )
            self._tx_ppp(PROTO_IP, ip_hdr + l4, f'ip_proto_{ip_proto}')

    def poll_udp_replies(self) -> None:
        """Forward any UDP responses waiting on bridged sockets back into PPP."""
        for (src_ip, src_port, dst_ip, dst_port), sock in list(self.udp_sockets.items()):
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                except BlockingIOError:
                    break
                except OSError:
                    break
                self.log_fn(
                    {
                        'event': 'tx_udp',
                        'src': f'{dst_ip}:{dst_port}',
                        'dst': f'{src_ip}:{src_port}',
                        'len': len(data),
                        'hex': data.hex(),
                        'ascii': ''.join(chr(b) if 32 <= b < 127 else '.' for b in data),
                    }
                )
                with self._tx_lock:
                    self.ip_id = (self.ip_id + 1) & 0xFFFF
                    pkt = build_ipv4_udp_packet(dst_ip, dst_port, src_ip, src_port, data, self.ip_id)
                    self._tx_ppp(PROTO_IP, pkt, f'udp_reply_{dst_port}->{src_port}')

    def close(self) -> None:
        with self._tx_lock:
            self.closed = True
        with self._delay_lock:
            if self._delay_q is not None:
                self._delay_q.put(None)
        if self.router is not None:
            self.router.unregister(self)
        for sock in self.udp_sockets.values():
            sock.close()
        self.udp_sockets.clear()
