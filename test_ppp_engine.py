import ipaddress
import socket
import struct
import threading
import time
import unittest

from ppp_engine import (
    CP_CONF_ACK,
    CP_CONF_NAK,
    CP_CONF_REJ,
    CP_CONF_REQ,
    FLAG,
    PROTO_IP,
    PROTO_IPCP,
    PROTO_LCP,
    PROTO_PAP,
    PppBridgeSession,
    PppRouter,
    build_cp_packet,
    build_ipv4_udp_packet,
    decode_ppp_frame,
    encode_ppp_frame,
    internet_checksum,
    parse_ipv4_packet,
)


def build_ipv4_tcp_packet(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x18,
    ip_id: int = 1,
) -> bytes:
    """Construct a complete IPv4 + TCP packet with valid header and TCP checksums."""
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed
    tcp_hdr_zero = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = src_b + dst_b + struct.pack('!BBH', 0, 6, len(tcp_hdr_zero) + len(payload))
    tcp_csum = internet_checksum(pseudo + tcp_hdr_zero + payload)
    tcp_seg = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, 0x50, flags, 65535, tcp_csum, 0) + payload

    total_len = 20 + len(tcp_seg)
    ip_hdr_zero = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ip_id & 0xFFFF, 0x4000, 64, 6, 0, src_b, dst_b)
    ip_csum = internet_checksum(ip_hdr_zero)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_len, ip_id & 0xFFFF, 0x4000, 64, 6, ip_csum, src_b, dst_b)
    return ip_hdr + tcp_seg


def extract_frames(stream: bytearray) -> list[bytes]:
    frames: list[bytes] = []
    parts = stream.split(bytes([FLAG]))
    # Everything between matched flags
    if len(parts) < 2:
        return frames
    for part in parts[1:-1]:
        if part:
            frames.append(part)
    stream[:] = FLAG.to_bytes(1, 'big') + parts[-1] if parts[-1] else b''
    return frames


class TestPppEngine(unittest.TestCase):
    def test_encode_decode_leading_and_trailing_flags(self) -> None:
        raw = encode_ppp_frame(PROTO_LCP, build_cp_packet(CP_CONF_ACK, 0x40, b'\x01\x04\x02\x00'))
        self.assertEqual(raw[0], FLAG)
        self.assertEqual(raw[-1], FLAG)
        decoded = decode_ppp_frame(raw[1:-1])
        self.assertTrue(decoded['fcs_ok'])
        self.assertEqual(decoded['proto_num'], PROTO_LCP)
        self.assertEqual(decoded['cp']['code'], CP_CONF_ACK)

    def test_decode_pfc_and_acfc_compressed_ip(self) -> None:
        udp_pkt = build_ipv4_udp_packet('192.168.167.2', 2000, '172.16.0.21', 9500, b'REQUEST_FILTER a')
        # Construct compressed PPP frame without FF 03 and 1-byte proto 0x21
        from ppp_engine import ppp_fcs

        body = b'\x21' + udp_pkt
        fcs = ppp_fcs(body) ^ 0xFFFF
        decoded = decode_ppp_frame(body + struct.pack('<H', fcs))
        self.assertTrue(decoded['fcs_ok'])
        self.assertEqual(decoded['proto_num'], PROTO_IP)
        parsed_ip = parse_ipv4_packet(decoded['payload'])
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(parsed_ip['dst_ip'], '172.16.0.21')
        self.assertEqual(parsed_ip['dst_port'], 9500)
        self.assertEqual(parsed_ip['udp_payload'], b'REQUEST_FILTER a')

    def test_lcp_and_ipcp_vj_accept_and_udp_roundtrip(self) -> None:
        # Echo UDP server simulating port 9500
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('127.0.0.1', 0))
        srv_port = srv.getsockname()[1]

        tx_buf = bytearray()
        logs: list[dict] = []
        sess = PppBridgeSession(tx_buf.extend, logs.append, vj_mode='accept', udp_target_host='127.0.0.1')
        try:
            # 1. Exact captured LCP CR from Frame Gride
            game_lcp_cr = bytes.fromhex('014000120104020007020802020600000000')
            sess.handle_frame(encode_ppp_frame(PROTO_LCP, game_lcp_cr)[1:-1])
            out1 = extract_frames(tx_buf)
            self.assertEqual(len(out1), 2)
            self.assertEqual(decode_ppp_frame(out1[0])['cp']['code'], CP_CONF_ACK)
            self.assertEqual(decode_ppp_frame(out1[1])['cp']['code'], CP_CONF_REQ)

            # 2. Game ACKs server LCP CR -> lcp_open; then game sends PAP -> server sends pap_ack + IPCP CR
            srv_lcp_cr = decode_ppp_frame(out1[1])['cp']
            sess.handle_frame(encode_ppp_frame(PROTO_LCP, build_cp_packet(CP_CONF_ACK, srv_lcp_cr['id'], srv_lcp_cr['data']))[1:-1])
            self.assertEqual(extract_frames(tx_buf), [])
            from ppp_engine import PROTO_PAP

            pap_req = bytes.fromhex('0a6672616d6567726964650c66726f6d736f667477617265')
            sess.handle_frame(encode_ppp_frame(PROTO_PAP, build_cp_packet(CP_CONF_REQ, 65, pap_req))[1:-1])
            out2 = extract_frames(tx_buf)
            self.assertEqual(len(out2), 2)
            self.assertEqual(decode_ppp_frame(out2[0])['proto_num'], PROTO_PAP)
            ipcp_cr = decode_ppp_frame(out2[1])
            self.assertEqual(ipcp_cr['proto_num'], PROTO_IPCP)
            opts = [o['type'] for o in ipcp_cr['cp']['options']]
            self.assertEqual(opts, [2, 3])

            # 3. Game sends IPCP CR requesting VJ + 0.0.0.0 -> server NAKs with 192.168.167.2
            game_ipcp_1 = b'\x02\x06\x00\x2d\x0f\x00\x03\x06\x00\x00\x00\x00'
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, 1, game_ipcp_1))[1:-1])
            out3 = extract_frames(tx_buf)
            self.assertEqual(len(out3), 1)
            self.assertEqual(decode_ppp_frame(out3[0])['cp']['code'], CP_CONF_NAK)

            # 4. Game retries IPCP CR with 192.168.167.2 & ACKs server IPCP CR
            game_ipcp_2 = b'\x02\x06\x00\x2d\x0f\x00\x03\x06\xc0\xa8\xa7\x02'
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, 2, game_ipcp_2))[1:-1])
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_ACK, ipcp_cr['cp']['id'], ipcp_cr['cp']['data']))[1:-1])
            out4 = extract_frames(tx_buf)
            self.assertEqual(decode_ppp_frame(out4[0])['cp']['code'], CP_CONF_ACK)
            self.assertTrue(any(l.get('event') == 'ipcp_open' for l in logs))

            # 5. Game sends IPv4 UDP packet to 172.16.0.21:srv_port -> echoed back as PPP IPv4 UDP
            pkt = build_ipv4_udp_packet('192.168.167.2', 10025, '172.16.0.21', srv_port, b'0 0 0 NICK Player')
            sess.handle_frame(encode_ppp_frame(PROTO_IP, pkt)[1:-1])
            data, peer = srv.recvfrom(4096)
            self.assertEqual(data, b'0 0 0 NICK Player')
            srv.sendto(b'100 111 222 Player', peer)
            # Wait briefly until kernel delivers loopback UDP datagram
            for _ in range(50):
                sess.poll_udp_replies()
                if tx_buf:
                    break
                threading.Event().wait(0.01)
            out5 = extract_frames(tx_buf)
            self.assertEqual(len(out5), 1)
            reply_ppp = decode_ppp_frame(out5[0])
            self.assertTrue(reply_ppp['fcs_ok'])
            reply_ip = parse_ipv4_packet(reply_ppp['payload'])
            self.assertEqual(reply_ip['src_ip'], '172.16.0.21')
            self.assertEqual(reply_ip['dst_ip'], '192.168.167.2')
            self.assertEqual(reply_ip['src_port'], srv_port)
            self.assertEqual(reply_ip['dst_port'], 10025)
            self.assertEqual(reply_ip['udp_payload'], b'100 111 222 Player')
        finally:
            sess.close()
            srv.close()

    def test_ipcp_vj_asymmetric_rejects_client_vj_but_offers_server_vj(self) -> None:
        tx_buf = bytearray()
        logs: list[dict] = []
        sess = PppBridgeSession(tx_buf.extend, logs.append, vj_mode='asymmetric')
        try:
            # 1. LCP + PAP bring-up -> server IPCP CR MUST include 02 06 00 2d 0f 00
            game_lcp_cr = bytes.fromhex('014000120104020007020802020600000000')
            sess.handle_frame(encode_ppp_frame(PROTO_LCP, game_lcp_cr)[1:-1])
            out1 = extract_frames(tx_buf)
            srv_lcp_cr = decode_ppp_frame(out1[1])['cp']
            sess.handle_frame(
                encode_ppp_frame(PROTO_LCP, build_cp_packet(CP_CONF_ACK, srv_lcp_cr['id'], srv_lcp_cr['data']))[1:-1]
            )
            extract_frames(tx_buf)

            pap_req = bytes.fromhex('0a6672616d6567726964650c66726f6d736f667477617265')
            sess.handle_frame(encode_ppp_frame(PROTO_PAP, build_cp_packet(CP_CONF_REQ, 65, pap_req))[1:-1])
            out2 = extract_frames(tx_buf)
            self.assertEqual(len(out2), 2)
            ipcp_cr = decode_ppp_frame(out2[1])
            self.assertEqual(ipcp_cr['proto_num'], PROTO_IPCP)
            self.assertEqual(ipcp_cr['cp']['code'], CP_CONF_REQ)
            self.assertEqual([o['type'] for o in ipcp_cr['cp']['options']], [2, 3])
            self.assertEqual(ipcp_cr['cp']['options'][0]['raw'], b'\x02\x06\x00\x2d\x0f\x00')

            # 2. Client IPCP CR with VJ option 2 -> server MUST send CP_CONF_REJ for option 2
            game_ipcp_vj = b'\x02\x06\x00\x2d\x0f\x00\x03\x06\x00\x00\x00\x00'
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, 1, game_ipcp_vj))[1:-1])
            out3 = extract_frames(tx_buf)
            self.assertEqual(len(out3), 1)
            rej_cp = decode_ppp_frame(out3[0])['cp']
            self.assertEqual(rej_cp['code'], CP_CONF_REJ)
            self.assertEqual([o['raw'] for o in rej_cp['options']], [b'\x02\x06\x00\x2d\x0f\x00'])

            # 3. Client strips option 2, requests 0.0.0.0 -> server NAKs with 192.168.167.2
            game_ipcp_no_vj_zero = b'\x03\x06\x00\x00\x00\x00'
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, 2, game_ipcp_no_vj_zero))[1:-1])
            out4 = extract_frames(tx_buf)
            self.assertEqual(len(out4), 1)
            nak_cp = decode_ppp_frame(out4[0])['cp']
            self.assertEqual(nak_cp['code'], CP_CONF_NAK)
            self.assertEqual(nak_cp['options'][0]['val'], ipaddress.IPv4Address('192.168.167.2').packed)

            # 4. Client retries without option 2 with 192.168.167.2 -> server ACKs & resends server IPCP CR (still with VJ)
            game_ipcp_final = b'\x03\x06\xc0\xa8\xa7\x02'
            sess.handle_frame(encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_REQ, 3, game_ipcp_final))[1:-1])
            out5 = extract_frames(tx_buf)
            self.assertEqual(len(out5), 2)
            self.assertEqual(decode_ppp_frame(out5[0])['cp']['code'], CP_CONF_ACK)
            srv_ipcp_cr2 = decode_ppp_frame(out5[1])['cp']
            self.assertEqual(srv_ipcp_cr2['code'], CP_CONF_REQ)
            self.assertEqual([o['type'] for o in srv_ipcp_cr2['options']], [2, 3])

            # 5. Client ACKs server IPCP CR -> ipcp_open
            sess.handle_frame(
                encode_ppp_frame(PROTO_IPCP, build_cp_packet(CP_CONF_ACK, srv_ipcp_cr2['id'], srv_ipcp_cr2['data']))[1:-1]
            )
            self.assertTrue(any(l.get('event') == 'ipcp_open' for l in logs))
        finally:
            sess.close()

    def _open_lcp(self, sess: PppBridgeSession, tx_buf: bytearray, game_lcp_cr: bytes) -> None:
        sess.handle_frame(encode_ppp_frame(PROTO_LCP, game_lcp_cr)[1:-1])
        srv_lcp_cr = decode_ppp_frame(extract_frames(tx_buf)[1])['cp']
        sess.handle_frame(
            encode_ppp_frame(PROTO_LCP, build_cp_packet(CP_CONF_ACK, srv_lcp_cr['id'], srv_lcp_cr['data']))[1:-1]
        )

    def test_tx_accm_follows_the_peer_once_lcp_is_open(self) -> None:
        tx_buf = bytearray()
        sess = PppBridgeSession(tx_buf.extend, lambda _: None, vj_mode='asymmetric')
        try:
            # RFC 1662 default until LCP opens: every control character is escaped.
            self.assertEqual(sess.tx_accm, 0xFFFFFFFF)
            game_lcp_cr = bytes.fromhex('014000120104020007020802020600000000')  # captured CR, ACCM option = 0
            sess.handle_frame(encode_ppp_frame(PROTO_LCP, game_lcp_cr)[1:-1])
            self.assertEqual(sess.tx_accm, 0xFFFFFFFF)  # our own CR is not acked yet
            srv_lcp_cr = decode_ppp_frame(extract_frames(tx_buf)[1])['cp']
            sess.handle_frame(
                encode_ppp_frame(PROTO_LCP, build_cp_packet(CP_CONF_ACK, srv_lcp_cr['id'], srv_lcp_cr['data']))[1:-1]
            )
            self.assertEqual(sess.tx_accm, 0)

            pkt = build_ipv4_tcp_packet('192.168.167.3', 1979, '192.168.167.2', 1979, b'\x00\x01\x11\x13')
            self.assertTrue(sess.deliver_ipv4(pkt))
            raw = bytes(tx_buf)
            self.assertEqual(raw, encode_ppp_frame(PROTO_IP, pkt, accm=0))
            self.assertLess(len(raw), len(encode_ppp_frame(PROTO_IP, pkt)))
            decoded = decode_ppp_frame(raw[1:-1])
            self.assertTrue(decoded['fcs_ok'])
            self.assertEqual(decoded['payload'], pkt)
        finally:
            sess.close()

    def test_encode_keeps_flag_and_escape_bytes_mapped_with_empty_accm(self) -> None:
        raw = encode_ppp_frame(PROTO_IP, b'\x7e\x7d\x00\x11', accm=0)
        self.assertEqual(raw.count(bytes([FLAG])), 2)  # only the two delimiters
        decoded = decode_ppp_frame(raw[1:-1])
        self.assertTrue(decoded['fcs_ok'])
        self.assertEqual(decoded['payload'], b'\x7e\x7d\x00\x11')

    def test_tx_accm_uses_the_peer_map_and_defaults_to_full_when_absent(self) -> None:
        mapped = bytearray()
        sess = PppBridgeSession(mapped.extend, lambda _: None, vj_mode='asymmetric')
        try:
            # Peer wants only XON/XOFF (0x11, 0x13) escaped: ACCM = 0x000A0000
            self._open_lcp(sess, mapped, bytes.fromhex('0140001201040200070208020206000a0000'))
            self.assertEqual(sess.tx_accm, 0x000A0000)
        finally:
            sess.close()

        absent = bytearray()
        sess = PppBridgeSession(absent.extend, lambda _: None, vj_mode='asymmetric')
        try:
            # No ACCM option at all -> the RFC default (map every control character) stays in force.
            self._open_lcp(sess, absent, bytes.fromhex('0140000c0104020007020802'))
            self.assertEqual(sess.tx_accm, 0xFFFFFFFF)
        finally:
            sess.close()

    def test_ppp_router_ip_allocation_and_reuse(self) -> None:
        router = PppRouter()
        tx1, tx2, tx3 = bytearray(), bytearray(), bytearray()
        s1 = PppBridgeSession(tx1.extend, lambda _: None, vj_mode='asymmetric', router=router)
        s2 = PppBridgeSession(tx2.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            self.assertEqual(s1.peer_ip, '192.168.167.2')
            self.assertEqual(s1.udp_bind_host, '127.0.0.2')
            self.assertEqual(s2.peer_ip, '192.168.167.3')
            self.assertEqual(s2.udp_bind_host, '127.0.0.3')
            self.assertIs(router.get_session('192.168.167.2'), s1)
            self.assertIs(router.get_session('192.168.167.3'), s2)

            # Closing/unregistering s1 frees .2 for reuse
            s1.close()
            self.assertIsNone(router.get_session('192.168.167.2'))

            s3 = PppBridgeSession(tx3.extend, lambda _: None, vj_mode='asymmetric', router=router)
            try:
                self.assertEqual(s3.peer_ip, '192.168.167.2')
                self.assertEqual(s3.udp_bind_host, '127.0.0.2')
                self.assertIs(router.get_session('192.168.167.2'), s3)
            finally:
                s3.close()
        finally:
            s1.close()
            s2.close()

    def test_ppp_router_bidirectional_p2p_tcp_and_udp_forwarding(self) -> None:
        router = PppRouter()
        tx_a, tx_b = bytearray(), bytearray()
        logs_a: list[dict] = []
        logs_b: list[dict] = []
        sess_a = PppBridgeSession(tx_a.extend, logs_a.append, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, logs_b.append, vj_mode='asymmetric', router=router)
        try:
            self.assertEqual(sess_a.peer_ip, '192.168.167.2')
            self.assertEqual(sess_b.peer_ip, '192.168.167.3')

            # 1. Raw TCP (proto=6) A -> B (port 1979) arrives unmodified as PROTO_IP at B
            tcp_a_to_b = build_ipv4_tcp_packet(
                '192.168.167.2', 41001, '192.168.167.3', 1979, b'FRAME_TCP_SYN', seq=10, ack=0, flags=0x02
            )
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, tcp_a_to_b)[1:-1])

            out_b = extract_frames(tx_b)
            self.assertEqual(len(out_b), 1)
            frame_b = decode_ppp_frame(out_b[0])
            self.assertTrue(frame_b['fcs_ok'])
            self.assertEqual(frame_b['proto_num'], PROTO_IP)
            self.assertEqual(frame_b['payload'], tcp_a_to_b)
            parsed_b = parse_ipv4_packet(frame_b['payload'])
            self.assertEqual(parsed_b['proto'], 6)
            self.assertEqual(parsed_b['src_ip'], '192.168.167.2')
            self.assertEqual(parsed_b['dst_ip'], '192.168.167.3')
            self.assertEqual(parsed_b['src_port'], 41001)
            self.assertEqual(parsed_b['dst_port'], 1979)
            self.assertTrue(any(l.get('event') == 'forward_p2p' and l.get('ip_proto') == 6 for l in logs_a))

            # 2. Raw TCP reply B -> A (1979 -> 41001) routes back unmodified to A
            tcp_b_to_a = build_ipv4_tcp_packet(
                '192.168.167.3', 1979, '192.168.167.2', 41001, b'FRAME_TCP_SYNACK', seq=20, ack=11, flags=0x12
            )
            sess_b.handle_frame(encode_ppp_frame(PROTO_IP, tcp_b_to_a)[1:-1])

            out_a = extract_frames(tx_a)
            self.assertEqual(len(out_a), 1)
            frame_a = decode_ppp_frame(out_a[0])
            self.assertTrue(frame_a['fcs_ok'])
            self.assertEqual(frame_a['proto_num'], PROTO_IP)
            self.assertEqual(frame_a['payload'], tcp_b_to_a)

            # 3. Bidirectional P2P UDP (proto=17) on port 1980
            udp_a_to_b = build_ipv4_udp_packet('192.168.167.2', 1980, '192.168.167.3', 1980, b'STATE_P1')
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, udp_a_to_b)[1:-1])
            out_b2 = extract_frames(tx_b)
            self.assertEqual(len(out_b2), 1)
            self.assertEqual(decode_ppp_frame(out_b2[0])['payload'], udp_a_to_b)

            udp_b_to_a = build_ipv4_udp_packet('192.168.167.3', 1980, '192.168.167.2', 1980, b'STATE_P2')
            sess_b.handle_frame(encode_ppp_frame(PROTO_IP, udp_b_to_a)[1:-1])
            out_a2 = extract_frames(tx_a)
            self.assertEqual(len(out_a2), 1)
            self.assertEqual(decode_ppp_frame(out_a2[0])['payload'], udp_b_to_a)

            # 4. After sess_b closes, packets to .3 no longer forward P2P
            sess_b.close()
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, tcp_a_to_b)[1:-1])
            self.assertEqual(extract_frames(tx_b), [])
            self.assertTrue(any(l.get('event') == 'rx_ip_other' and l.get('dst') == '192.168.167.3' for l in logs_a))
        finally:
            sess_a.close()
            sess_b.close()

    def test_p2p_delay_holds_frames_back_and_keeps_their_order(self) -> None:
        import time

        router = PppRouter(p2p_delay_ms=60)
        tx_a, tx_b = bytearray(), bytearray()
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            first = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'FIRST', seq=1)
            second = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'SECOND', seq=2)
            sent_at = time.monotonic()
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, first)[1:-1])
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, second)[1:-1])
            self.assertEqual(bytes(tx_b), b'')  # nothing is delivered synchronously any more

            deadline = sent_at + 2.0
            while len(extract_frames(bytearray(tx_b))) < 2 and time.monotonic() < deadline:
                threading.Event().wait(0.005)
            arrived_after = time.monotonic() - sent_at
            self.assertGreaterEqual(arrived_after, 0.055)
            self.assertLess(arrived_after, 1.0)

            frames = extract_frames(tx_b)
            self.assertEqual([decode_ppp_frame(f)['payload'] for f in frames], [first, second])
        finally:
            sess_a.close()
            sess_b.close()

    def test_p2p_delay_zero_still_delivers_at_once(self) -> None:
        router = PppRouter(p2p_delay_ms=0)
        tx_a, tx_b = bytearray(), bytearray()
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            pkt = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'NOW')
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, pkt)[1:-1])
            self.assertEqual(len(extract_frames(tx_b)), 1)
        finally:
            sess_a.close()
            sess_b.close()

    def _send_burst(self, router: PppRouter, count: int) -> tuple[int, list[dict]]:
        """Send `count` console-to-console packets through `router`; return how many arrive and the receiver's log."""
        tx_a, tx_b, events = bytearray(), bytearray(), []
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, events.append, vj_mode='asymmetric', router=router)
        try:
            for seq in range(count):
                pkt = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'X', seq=seq)
                sess_a.handle_frame(encode_ppp_frame(PROTO_IP, pkt)[1:-1])
            threading.Event().wait(0.3)
            arrived = [decode_ppp_frame(f)['payload'] for f in extract_frames(tx_b)]
            return len(arrived), events
        finally:
            sess_a.close()
            sess_b.close()

    def test_p2p_loss_of_100_percent_delivers_nothing_and_logs_each_drop(self) -> None:
        arrived, events = self._send_burst(PppRouter(p2p_loss_pct=100), 5)
        self.assertEqual(arrived, 0)
        self.assertEqual(len([e for e in events if e.get('event') == 'p2p_drop']), 5)

    def test_p2p_loss_of_zero_delivers_everything(self) -> None:
        arrived, _ = self._send_burst(PppRouter(p2p_loss_pct=0), 20)
        self.assertEqual(arrived, 20)

    def test_p2p_loss_follows_the_seed_so_a_run_can_be_repeated(self) -> None:
        first, _ = self._send_burst(PppRouter(p2p_loss_pct=30, p2p_seed=7), 100)
        second, _ = self._send_burst(PppRouter(p2p_loss_pct=30, p2p_seed=7), 100)
        self.assertEqual(first, second)
        self.assertTrue(50 <= first <= 90, first)

    def test_p2p_jitter_spreads_the_delay_but_keeps_the_order(self) -> None:
        router = PppRouter(p2p_delay_ms=5, p2p_jitter_ms=60, p2p_seed=3)
        tx_a, tx_b = bytearray(), bytearray()
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            sent = []
            for seq in range(15):
                pkt = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'J', seq=seq)
                sent.append(pkt)
                sess_a.handle_frame(encode_ppp_frame(PROTO_IP, pkt)[1:-1])
            deadline = time.monotonic() + 3.0
            while len(extract_frames(bytearray(tx_b))) < 15 and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertEqual([decode_ppp_frame(f)['payload'] for f in extract_frames(tx_b)], sent)
        finally:
            sess_a.close()
            sess_b.close()

    def test_p2p_delay_drops_frames_for_a_closed_session(self) -> None:
        router = PppRouter(p2p_delay_ms=20)
        tx_a, tx_b = bytearray(), bytearray()
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            pkt = build_ipv4_tcp_packet('192.168.167.2', 1979, '192.168.167.3', 1979, b'LATE')
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, pkt)[1:-1])
            sess_b.close()
            threading.Event().wait(0.15)
            self.assertEqual(bytes(tx_b), b'')
        finally:
            sess_a.close()
            sess_b.close()

    def test_ppp_router_distinct_udp_bind_hosts_to_lobby(self) -> None:
        lobby = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        lobby.bind(('127.0.0.1', 0))
        lobby_port = lobby.getsockname()[1]

        router = PppRouter()
        tx_a, tx_b = bytearray(), bytearray()
        sess_a = PppBridgeSession(tx_a.extend, lambda _: None, vj_mode='asymmetric', router=router)
        sess_b = PppBridgeSession(tx_b.extend, lambda _: None, vj_mode='asymmetric', router=router)
        try:
            pkt_a = build_ipv4_udp_packet('192.168.167.2', 2001, '172.16.0.21', lobby_port, b'HELLO_A')
            pkt_b = build_ipv4_udp_packet('192.168.167.3', 2001, '172.16.0.21', lobby_port, b'HELLO_B')
            sess_a.handle_frame(encode_ppp_frame(PROTO_IP, pkt_a)[1:-1])
            sess_b.handle_frame(encode_ppp_frame(PROTO_IP, pkt_b)[1:-1])

            seen: dict[bytes, str] = {}
            lobby.settimeout(1.0)
            for _ in range(2):
                data, addr = lobby.recvfrom(4096)
                seen[data] = addr[0]

            self.assertEqual(seen[b'HELLO_A'], '127.0.0.2')
            self.assertEqual(seen[b'HELLO_B'], '127.0.0.3')
        finally:
            sess_a.close()
            sess_b.close()
            lobby.close()


if __name__ == '__main__':
    unittest.main()
