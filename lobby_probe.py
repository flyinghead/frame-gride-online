from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import selectors
import socket
import time

LOG_PATH = Path(__file__).resolve().parent / 'lobby-probe.jsonl'
CMD_RE = re.compile(rb'^(\d+)\s+(\d+)\s+(\d+)\s+([A-Z0-9_]+)(?:\s+(.*))?$', re.DOTALL)
GAME_NAME_SJIS = 'フレームグライド'.encode('shift_jis')


def clean_nul(data: bytes) -> bytes:
    """Trim fixed-size UDP buffers at the first NUL byte."""
    nul = data.find(b'\x00')
    return data[:nul] if nul != -1 else data


def ppp_ip_for_peer(peer_host: str) -> str:
    """Map a local loopback peer host to the Dreamcast client's PPP IP."""
    if peer_host == '127.0.0.1':
        return '192.168.167.2'
    if peer_host.startswith('127.0.0.'):
        tail = peer_host.removeprefix('127.0.0.')
        if tail.isdigit() and int(tail) >= 2:
            return f'192.168.167.{int(tail)}'
    return '192.168.167.2'


def log_event(entry: dict) -> None:
    line = json.dumps(entry, ensure_ascii=False)
    print(line, flush=True)
    with LOG_PATH.open('a', encoding='utf-8') as f:
        f.write(line + '\n')


@dataclass
class ClientSession:
    """Per-client state keyed by UDP peer address on lobby port 9501."""

    peer_addr: tuple[str, int]
    uid: int
    ppp_ip: str
    tok: int = 222
    nick_bytes: bytes = b'Player'
    channel: bytes = b'Lobby1'
    game_name: bytes = GAME_NAME_SJIS
    game_selected: bool = False
    team_name: bytes = b''
    user_hex60: bytes = b'#'


@dataclass
class TeamState:
    """Active lobby team in a channel; member_peers[0] is always the leader."""

    name: bytes
    channel: bytes
    max_players: bytes = b'2'
    password: bytes = b''
    game_name: bytes = GAME_NAME_SJIS
    member_peers: list[tuple[str, int]] = field(default_factory=list)
    team_hex60: bytes = b''


class LobbyServer:
    """Multi-client Frame Gride lobby server implementing exact 1ST_READ.BIN formats."""

    def __init__(self) -> None:
        self.clients: dict[tuple[str, int], ClientSession] = {}
        self.teams: dict[tuple[bytes, bytes], TeamState] = {}
        self._next_uid: int = 111

    def _get_or_create_client(self, peer_addr: tuple[str, int]) -> ClientSession:
        client = self.clients.get(peer_addr)
        if client is None:
            client = ClientSession(
                peer_addr=peer_addr,
                uid=self._next_uid,
                ppp_ip=ppp_ip_for_peer(peer_addr[0]),
            )
            self._next_uid += 1
            self.clients[peer_addr] = client
        return client

    def _channel_clients(self, channel: bytes) -> list[ClientSession]:
        if not channel:
            return []
        return [c for c in self.clients.values() if c.channel == channel]

    def _channel_recipients(self, sender: ClientSession, channel: bytes | None = None) -> list[ClientSession]:
        target_chan = sender.channel if channel is None else channel
        members = self._channel_clients(target_chan)
        ordered = [sender] if sender in members or channel is None else []
        for member in members:
            if member is not sender:
                ordered.append(member)
        return ordered

    def _get_team(self, channel: bytes, team_name: bytes) -> TeamState | None:
        if not team_name:
            return None
        return self.teams.get((channel, team_name))

    def _get_client_team(self, client: ClientSession) -> TeamState | None:
        if not client.team_name:
            return None
        return self.teams.get((client.channel, client.team_name))

    def _remove_from_team(self, client: ClientSession) -> None:
        team = self._get_client_team(client)
        if team is not None:
            team.member_peers = [p for p in team.member_peers if p != client.peer_addr]
            if not team.member_peers:
                self.teams.pop((team.channel, team.name), None)
        client.team_name = b''

    def _team_members(self, team: TeamState) -> list[ClientSession]:
        return [self.clients[p] for p in team.member_peers if p in self.clients]

    def _broadcast(
        self,
        recipients: list[ClientSession],
        payload: bytes,
        delay: float = 0.01,
    ) -> list[tuple[float, tuple[str, int], bytes]]:
        seen: set[tuple[str, int]] = set()
        out: list[tuple[float, tuple[str, int], bytes]] = []
        for recipient in recipients:
            if recipient.peer_addr not in seen:
                seen.add(recipient.peer_addr)
                out.append((delay, recipient.peer_addr, payload))
        return out

    def handle_datagram(
        self,
        trimmed: bytes,
        peer_addr: tuple[str, int] = ('127.0.0.1', 0),
    ) -> list[tuple[float, tuple[str, int], bytes]]:
        """Process one incoming datagram and return [(delay, target_peer, payload), ...]."""
        if trimmed.startswith(b'REQUEST_FILTER'):
            return [
                (0.00, peer_addr, b'1000 1'),
                (0.05, peer_addr, b'1001 FrameGrideLocal 172.16.0.21 9501'),
                (0.10, peer_addr, b'1002'),
            ]

        m = CMD_RE.match(trimmed)
        if not m:
            return []

        cmd = m.group(4)
        rest = (m.group(5) or b'').strip()

        if cmd == b'KEEPALIVE':
            return [(0.00, peer_addr, b'0')]

        client = self._get_or_create_client(peer_addr)

        if cmd == b'NICK' and rest:
            client.nick_bytes = rest
            header = f'100 {client.uid} {client.tok} '.encode('ascii')
            return [(0.01, peer_addr, header + rest)]

        if cmd == b'USER':
            chan = client.channel or b'Lobby1'
            return [(0.01, peer_addr, b'101 1 0 ' + chan)]

        if cmd == b'LIST':
            chan = client.channel or b'Lobby1'
            user_count = len(self._channel_clients(chan)) or 1
            return [
                (0.01, peer_addr, b'109 ' + chan + b' ' + str(user_count).encode('ascii') + b' 32 :TestLobby'),
                (0.06, peer_addr, b'110'),
            ]

        if cmd == b'GAMELIST':
            return [
                (0.01, peer_addr, b'116 1 ' + client.game_name),
                (0.05, peer_addr, b'117'),
            ]

        if cmd == b'SELECTGAME':
            game = rest or client.game_name
            client.game_name = game
            client.game_selected = True
            payload = b'123 ' + client.nick_bytes + b' ' + game
            return self._broadcast(self._channel_recipients(client), payload)

        if cmd == b'JOIN':
            channel = rest.split(b' ')[0] if rest else (client.channel or b'Lobby1')
            if client.channel != channel:
                self._remove_from_team(client)
            client.channel = channel
            payload = b'102 ' + channel + b' ' + client.nick_bytes
            return self._broadcast(self._channel_recipients(client, channel), payload)

        if cmd == b'PART':
            recipients = self._channel_recipients(client)
            self._remove_from_team(client)
            client.channel = b''
            return self._broadcast(recipients, b'103 ' + client.nick_bytes)

        if cmd == b'WHO':
            chan = client.channel or b'Lobby1'
            users = self._channel_clients(chan)
            replies: list[tuple[float, tuple[str, int], bytes]] = []
            for user in users:
                team = self._get_client_team(user)
                if team is not None:
                    members = self._team_members(team)
                    is_leader = bool(members and members[0].peer_addr == user.peer_addr)
                    nick_tok = (b'*' + user.nick_bytes) if is_leader else user.nick_bytes
                    team_tok = b':' + team.name
                else:
                    nick_tok = user.nick_bytes
                    team_tok = b'#'
                udata_tok = (b':' + user.user_hex60) if user.user_hex60 != b'#' else b'#'
                game_tok = (b':' + user.game_name) if (team is not None or user.game_selected) else b'#'
                who_line = (
                    b'104 ' + chan + b' ' + nick_tok + b' 0 '
                    + team_tok + b' ' + udata_tok + b' ' + game_tok
                )
                replies.append((0.01, peer_addr, who_line))
            replies.append((0.05, peer_addr, b'105'))
            return replies

        if cmd == b'WHOIS':
            target_nick = rest.split(b' ')[0] if rest else b''
            target = next((c for c in self.clients.values() if c.nick_bytes == target_nick), None)
            if target is None:
                return []
            chan_tok = (b':' + target.channel) if target.channel else b'#'
            team_tok = (b':' + target.team_name) if target.team_name else b'#'
            replies = [(0.01, peer_addr, b'106 ' + target.nick_bytes + b' ' + chan_tok + b' ' + team_tok)]
            if target.user_hex60 != b'#':
                replies.append((0.02, peer_addr, b'170 ' + target.nick_bytes + b' ' + target.user_hex60))
            if target.game_selected:
                replies.append((0.03, peer_addr, b'123 ' + target.nick_bytes + b' ' + target.game_name))
            return replies

        if cmd == b'TEAMLIST':
            chan = client.channel or b'Lobby1'
            channel_teams = [t for t in self.teams.values() if t.channel == chan and t.member_peers]
            if not channel_teams:
                return [(0.01, peer_addr, b'119')]
            replies = []
            for team in channel_teams:
                members = self._team_members(team)
                if not members:
                    continue
                member_tokens = b' '.join(
                    (b'*' + member.nick_bytes) if i == 0 else member.nick_bytes
                    for i, member in enumerate(members)
                )
                flags = b'8' if team.password else b'0'
                pass_tok = (b':' + team.password) if team.password else b'#'
                line = (
                    b'118 ' + team.name + b' '
                    + str(len(members)).encode('ascii') + b' '
                    + team.max_players + b' '
                    + flags + b' ' + pass_tok + b' '
                    + member_tokens + b' ' + team.game_name
                )
                replies.append((0.01, peer_addr, line))
            replies.append((0.05, peer_addr, b'119'))
            return replies

        if cmd == b'CREATETEAM':
            self._remove_from_team(client)
            tokens = [t for t in rest.split(b' ') if t]
            max_players = b'2'
            mode_and_pw = b''
            if len(tokens) >= 2 and tokens[0].isdigit():
                max_players = tokens[0]
                team_name = tokens[1]
                mode_and_pw = tokens[2] if len(tokens) >= 3 else b''
            elif tokens:
                team_name = tokens[0]
                mode_and_pw = tokens[1] if len(tokens) >= 2 else b''
            else:
                team_name = b'Team1'

            password = b''
            if b':' in mode_and_pw:
                _, _, password = mode_and_pw.partition(b':')
            elif b':' in team_name:
                team_name, _, password = team_name.partition(b':')

            chan = client.channel or b'Lobby1'
            client.channel = chan
            team = TeamState(
                name=team_name,
                channel=chan,
                max_players=max_players,
                password=password,
                game_name=client.game_name,
                member_peers=[client.peer_addr],
            )
            self.teams[(chan, team_name)] = team
            client.team_name = team_name
            flags = b'8' if password else b'0'
            payload = (
                b'120 ' + team_name + b' ' + client.nick_bytes + b' '
                + max_players + b' ' + flags + b' ' + team.game_name
            )
            return self._broadcast(self._channel_recipients(client, chan), payload)

        if cmd == b'JOINTEAM':
            tokens = [t for t in rest.split(b' ') if t]
            team_name = tokens[0] if tokens else (client.team_name or b'Team1')
            password = tokens[1] if len(tokens) >= 2 else b''
            chan = client.channel or b'Lobby1'
            team = self._get_team(chan, team_name)
            if team is None:
                return []
            if client.peer_addr not in team.member_peers:
                if team.password and password != team.password:
                    return []
                self._remove_from_team(client)
                team.member_peers.append(client.peer_addr)
                client.team_name = team.name
            members = self._team_members(team)
            member_nicks = b' '.join(member.nick_bytes for member in members)
            payload = b'121 ' + team.name + b' ' + member_nicks
            return self._broadcast(self._channel_recipients(client, chan), payload)

        if cmd == b'LEAVETEAM':
            team = self._get_client_team(client)
            team_name = team.name if team is not None else (client.team_name or b'Team1')
            recipients = self._channel_recipients(client)
            if team is not None:
                for member in self._team_members(team):
                    if member not in recipients:
                        recipients.append(member)
            self._remove_from_team(client)
            payload = b'122 ' + team_name + b' ' + client.nick_bytes
            return self._broadcast(recipients, payload)

        if cmd == b'PRIVMSG':
            target, sep, msg = rest.partition(b' ')
            if target.startswith(b'#'):
                if not sep or not msg:
                    return []
                chan = target[1:] or client.channel or b'Lobby1'
                payload = b'114 ' + client.nick_bytes + b' ' + msg
                return self._broadcast(self._channel_recipients(client, chan), payload)
            text_msg = msg if sep else b''
            if not text_msg:
                return []
            payload = b'115 ' + client.nick_bytes + b' ' + text_msg
            targets = [c for c in self.clients.values() if c.nick_bytes == target]
            if not targets:
                targets = [client]
            return self._broadcast(targets, payload)

        if cmd == b'TEAMMSG':
            if not rest:
                return []
            team = self._get_client_team(client)
            recipients = self._team_members(team) if team is not None else [client]
            if client not in recipients:
                recipients.insert(0, client)
            return self._broadcast(recipients, b'131 ' + client.nick_bytes + b' ' + rest)

        if cmd == b'PLAY':
            team = self._get_client_team(client)
            members = self._team_members(team) if team is not None else [client]
            if not members:
                members = [client]
            entries = [
                ((b'*' + member.nick_bytes) if i == 0 else member.nick_bytes)
                + b' ' + member.ppp_ip.encode('ascii')
                for i, member in enumerate(members)
            ]
            payload = b'124 ' + str(len(members)).encode('ascii') + b' ' + b' '.join(entries)
            return self._broadcast(members, payload)

        if cmd == b'CHANGEUSERDATA':
            if rest:
                tok = rest.split(b' ')[0]
                if tok:
                    client.user_hex60 = tok
                    payload = b'170 ' + client.nick_bytes + b' ' + tok
                    return self._broadcast(self._channel_recipients(client), payload)
            return []

        if cmd == b'SETTEAMDATA':
            tokens = [t for t in rest.split(b' ') if t]
            if len(tokens) >= 2:
                team_name, tok = tokens[0], tokens[1]
                chan = client.channel or b'Lobby1'
                team = self._get_team(chan, team_name) or self._get_client_team(client)
                target_name = team.name if team is not None else team_name
                if team is not None:
                    team.team_hex60 = tok
                recipients = self._channel_recipients(client, chan)
                if team is not None:
                    for member in self._team_members(team):
                        if member not in recipients:
                            recipients.append(member)
                return self._broadcast(recipients, b'171 ' + target_name + b' ' + tok)
            return []

        if cmd == b'RECONNECT':
            return [(0.01, peer_addr, b'125')]

        if cmd in (b'LAUNCH_MODULE', b'RESULT', b'START', b'WIN', b'LOSE'):
            return []

        if cmd == b'QUIT':
            self._remove_from_team(client)
            client.channel = b''
            self.clients.pop(peer_addr, None)
            return []

        return []


class LobbyProbeState:
    """Single-session compatibility wrapper around LobbyServer."""

    def __init__(
        self,
        server: LobbyServer | None = None,
        peer_addr: tuple[str, int] = ('127.0.0.1', 0),
    ) -> None:
        self.server = server or LobbyServer()
        self.peer_addr = peer_addr

    def build_replies(
        self,
        trimmed: bytes,
        peer_addr: tuple[str, int] | None = None,
    ) -> list[tuple[float, bytes]]:
        """Return list of (delay_seconds, reply_bytes) for one incoming game UDP command."""
        addr = self.peer_addr if peer_addr is None else peer_addr
        return [
            (delay, payload)
            for delay, _target, payload in self.server.handle_datagram(trimmed, addr)
        ]


def build_replies_for_datagram(trimmed: bytes, state: LobbyProbeState | None = None) -> list[tuple[float, bytes]]:
    return (state or LobbyProbeState()).build_replies(trimmed)


def main() -> None:
    LOG_PATH.write_text('', encoding='utf-8')
    sel = selectors.DefaultSelector()
    sockets: dict[int, socket.socket] = {}
    for port in (9500, 9501):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', port))
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, data=port)
        sockets[port] = sock

    log_event({'listening': [['127.0.0.1', 9500], ['127.0.0.1', 9501]], 'mode': 'lobby_probe'})
    pending_sends: list[tuple[float, socket.socket, tuple[str, int], bytes]] = []
    server = LobbyServer()

    try:
        while True:
            now = time.monotonic()
            still_pending = []
            for due, sock, peer, payload in pending_sends:
                if now >= due:
                    sock.sendto(payload, peer)
                    log_event(
                        {
                            'event': 'tx_udp',
                            'local_port': sock.getsockname()[1],
                            'peer': list(peer),
                            'text': payload.decode('shift_jis', errors='replace'),
                        }
                    )
                else:
                    still_pending.append((due, sock, peer, payload))
            pending_sends = still_pending

            timeout = 0.02 if pending_sends else 0.1
            for key, _ in sel.select(timeout=timeout):
                sock: socket.socket = key.fileobj  # type: ignore[assignment]
                local_port: int = key.data
                raw, peer = sock.recvfrom(4096)
                trimmed = clean_nul(raw).rstrip(b'\r\n')
                text = trimmed.decode('shift_jis', errors='replace')
                log_event(
                    {
                        'event': 'rx_udp',
                        'local_port': local_port,
                        'peer': list(peer),
                        'raw_len': len(raw),
                        'trimmed_text': text,
                        'trimmed_hex': trimmed.hex(),
                    }
                )
                base_t = time.monotonic()
                for delay, target_peer, msg in server.handle_datagram(trimmed, peer):
                    pending_sends.append((base_t + delay, sock, target_peer, msg))
    finally:
        for sock in sockets.values():
            sock.close()


if __name__ == '__main__':
    main()
