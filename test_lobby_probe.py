import unittest

from lobby_probe import (
    GAME_NAME_SJIS,
    LobbyProbeState,
    LobbyServer,
    build_replies_for_datagram,
    clean_nul,
    ppp_ip_for_peer,
)


class TestLobbyProbe(unittest.TestCase):
    def test_clean_nul_trims_trailing_garbage(self) -> None:
        raw = b'REQUEST_FILTER \x00\xcc\x6f\x0e'
        self.assertEqual(clean_nul(raw), b'REQUEST_FILTER ')

    def test_ppp_ip_for_peer(self) -> None:
        self.assertEqual(ppp_ip_for_peer('127.0.0.1'), '192.168.167.2')
        self.assertEqual(ppp_ip_for_peer('127.0.0.2'), '192.168.167.2')
        self.assertEqual(ppp_ip_for_peer('127.0.0.3'), '192.168.167.3')
        self.assertEqual(ppp_ip_for_peer('127.0.0.12'), '192.168.167.12')
        self.assertEqual(ppp_ip_for_peer('10.0.0.5'), '192.168.167.2')

    def test_request_filter_returns_1000_1001_1002(self) -> None:
        replies = build_replies_for_datagram(b'REQUEST_FILTER ')
        self.assertEqual([r[1] for r in replies], [
            b'1000 1',
            b'1001 FrameGrideLocal 172.16.0.21 9501',
            b'1002',
        ])

    def test_nick_user_list_gamelist_selectgame_and_keepalive(self) -> None:
        st = LobbyProbeState()
        sjis_a = 'あ'.encode('shift_jis')
        self.assertEqual([r[1] for r in st.build_replies(b'0 0 0 NICK ' + sjis_a)], [
            b'100 111 222 ' + sjis_a,
        ])
        user_pkt = b'111 0 222 USER :' + sjis_a + b' : : :46981434472A'
        self.assertEqual([r[1] for r in st.build_replies(user_pkt)], [
            b'101 1 0 Lobby1',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 1 222 LIST')], [
            b'109 Lobby1 1 32 :TestLobby',
            b'110',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 2 222 GAMELIST')], [
            b'116 1 ' + GAME_NAME_SJIS,
            b'117',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 3 222 SELECTGAME ' + GAME_NAME_SJIS)], [
            b'123 ' + sjis_a + b' ' + GAME_NAME_SJIS,
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 4 222 KEEPALIVE')], [
            b'0',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 6 222 JOIN Lobby1 ')], [
            b'102 Lobby1 ' + sjis_a,
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 6 222 WHO')], [
            b'104 Lobby1 ' + sjis_a + b' 0 # # :' + GAME_NAME_SJIS,
            b'105',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 7 222 TEAMLIST')], [
            b'119',
        ])

    def test_chat_and_team_lifecycle(self) -> None:
        st = LobbyProbeState()
        sjis_a = 'あ'.encode('shift_jis')
        st.build_replies(b'0 0 0 NICK ' + sjis_a)

        self.assertEqual([r[1] for r in st.build_replies(b'111 8 222 PRIVMSG #Lobby1 hello')], [
            b'114 ' + sjis_a + b' hello',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 9 222 PRIVMSG Bob hi')], [
            b'115 ' + sjis_a + b' hi',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 10 222 CREATETEAM 2 TeamA NORMAL')], [
            b'120 TeamA ' + sjis_a + b' 2 0 ' + GAME_NAME_SJIS,
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 11 222 WHO')], [
            b'104 Lobby1 *' + sjis_a + b' 0 :TeamA # :' + GAME_NAME_SJIS,
            b'105',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 12 222 TEAMLIST')], [
            b'118 TeamA 1 2 0 # *' + sjis_a + b' ' + GAME_NAME_SJIS,
            b'119',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 13 222 TEAMMSG ready')], [
            b'131 ' + sjis_a + b' ready',
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 14 222 JOINTEAM TeamA')], [
            b'121 TeamA ' + sjis_a,
        ])
        self.assertEqual([r[1] for r in st.build_replies(b'111 15 222 LEAVETEAM')], [
            b'122 TeamA ' + sjis_a,
        ])

    def test_multi_client_lobby_team_play_and_chat(self) -> None:
        srv = LobbyServer()
        p1 = ('127.0.0.2', 50001)
        p2 = ('127.0.0.3', 50002)

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'0 0 0 NICK P1', p1)],
            [(p1, b'100 111 222 P1')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'0 0 0 NICK P2', p2)],
            [(p2, b'100 112 222 P2')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 0 222 USER :P1 : : :4698', p1)],
            [(p1, b'101 1 0 Lobby1')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 0 222 USER :P2 : : :4699', p2)],
            [(p2, b'101 1 0 Lobby1')],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 1 222 JOIN Lobby1', p1)],
            [(p1, b'102 Lobby1 P1'), (p2, b'102 Lobby1 P1')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 1 222 JOIN Lobby1', p2)],
            [(p2, b'102 Lobby1 P2'), (p1, b'102 Lobby1 P2')],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 2 222 WHO', p1)],
            [
                (p1, b'104 Lobby1 P1 0 # # #'),
                (p1, b'104 Lobby1 P2 0 # # #'),
                (p1, b'105'),
            ],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 3 222 CREATETEAM 2 TeamA NORMAL', p1)],
            [
                (p1, b'120 TeamA P1 2 0 ' + GAME_NAME_SJIS),
                (p2, b'120 TeamA P1 2 0 ' + GAME_NAME_SJIS),
            ],
        )

        # 121 MUST NOT include '*' prefix on member nicks (FUN_8c0ada58 matches GET_LOCAL_NICK directly).
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 2 222 JOINTEAM TeamA', p2)],
            [
                (p2, b'121 TeamA P1 P2'),
                (p1, b'121 TeamA P1 P2'),
            ],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 3 222 TEAMLIST', p2)],
            [
                (p2, b'118 TeamA 2 2 0 # *P1 P2 ' + GAME_NAME_SJIS),
                (p2, b'119'),
            ],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 4 222 TEAMMSG 00', p1)],
            [(p1, b'131 P1 00'), (p2, b'131 P1 00')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 5 222 TEAMMSG START', p1)],
            [(p1, b'131 P1 START'), (p2, b'131 P1 START')],
        )

        expected_play = b'124 2 *P1 192.168.167.2 P2 192.168.167.3'
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 6 222 PLAY', p1)],
            [(p1, expected_play), (p2, expected_play)],
        )

        # Channel chat and direct whisper
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 7 222 PRIVMSG #Lobby1 glhf', p1)],
            [(p1, b'114 P1 glhf'), (p2, b'114 P1 glhf')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 8 222 PRIVMSG P2 secret', p1)],
            [(p2, b'115 P1 secret')],
        )

        # Leader leaves -> P2 promoted to leader; then P2 leaves -> team deleted
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 9 222 LEAVETEAM', p1)],
            [(p1, b'122 TeamA P1'), (p2, b'122 TeamA P1')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 4 222 TEAMLIST', p2)],
            [
                (p2, b'118 TeamA 1 2 0 # *P2 ' + GAME_NAME_SJIS),
                (p2, b'119'),
            ],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 5 222 LEAVETEAM', p2)],
            [(p2, b'122 TeamA P2'), (p1, b'122 TeamA P2')],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 6 222 TEAMLIST', p2)],
            [(p2, b'119')],
        )

    def test_passworded_team_and_lifecycle_commands(self) -> None:
        srv = LobbyServer()
        p1 = ('127.0.0.1', 40001)
        p2 = ('127.0.0.1', 40002)

        srv.handle_datagram(b'0 0 0 NICK Alpha', p1)
        srv.handle_datagram(b'0 0 0 NICK Beta', p2)
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 1 222 CHANGEUSERDATA DEADBEEF', p1)],
            [
                (p1, b'170 Alpha DEADBEEF'),
                (p2, b'170 Alpha DEADBEEF'),
            ],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 0 222 WHOIS Alpha', p2)],
            [
                (p2, b'106 Alpha :Lobby1 #'),
                (p2, b'170 Alpha DEADBEEF'),
            ],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 2 222 CREATETEAM 2 SecTeam NORMAL:pw', p1)],
            [
                (p1, b'120 SecTeam Alpha 2 8 ' + GAME_NAME_SJIS),
                (p2, b'120 SecTeam Alpha 2 8 ' + GAME_NAME_SJIS),
            ],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 1 222 TEAMLIST', p2)],
            [
                (p2, b'118 SecTeam 1 2 8 :pw *Alpha ' + GAME_NAME_SJIS),
                (p2, b'119'),
            ],
        )
        # Wrong password rejected; right password succeeds
        self.assertEqual(srv.handle_datagram(b'112 2 222 JOINTEAM SecTeam bad', p2), [])
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 3 222 JOINTEAM SecTeam pw', p2)],
            [
                (p2, b'121 SecTeam Alpha Beta'),
                (p1, b'121 SecTeam Alpha Beta'),
            ],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 3 222 SETTEAMDATA SecTeam 0100', p1)],
            [
                (p1, b'171 SecTeam 0100'),
                (p2, b'171 SecTeam 0100'),
            ],
        )
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 3 222 WHO', p1)],
            [
                (p1, b'104 Lobby1 *Alpha 0 :SecTeam :DEADBEEF :' + GAME_NAME_SJIS),
                (p1, b'104 Lobby1 Beta 0 :SecTeam # :' + GAME_NAME_SJIS),
                (p1, b'105'),
            ],
        )

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'111 4 222 RECONNECT', p1)],
            [(p1, b'125')],
        )
        for cmd in (b'LAUNCH_MODULE', b'RESULT 1', b'START', b'WIN', b'LOSE'):
            self.assertEqual(srv.handle_datagram(b'111 4 222 ' + cmd, p1), [])

        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 4 222 PART', p2)],
            [(p2, b'103 Beta'), (p1, b'103 Beta')],
        )
        self.assertEqual(srv.handle_datagram(b'111 5 222 QUIT', p1), [])
        self.assertEqual(
            [(t, p) for _, t, p in srv.handle_datagram(b'112 5 222 TEAMLIST', p2)],
            [(p2, b'119')],
        )


if __name__ == '__main__':
    unittest.main()
