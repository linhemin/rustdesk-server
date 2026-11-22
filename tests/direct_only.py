"""Exercise hbbs/hbbr policy using real TCP, WebSocket and encrypted clients."""
import base64
import os
import socket
import subprocess
import sys
import tempfile
from contextlib import ExitStack, closing
from pathlib import Path

import websocket

from p2p_signaling import (SecureConnection, description, expect_no_packet, field, parse,
                           read_tcp, relay_address, send_tcp, wait_for_server)

REQUIRED = b"Direct connection required by server"
UNAVAILABLE = b"Direct connection unavailable in direct-only mode"
PEER = b"824165901"
VERSION = b"1.5.3"
RELAY = b"hbbr.invalid:21117"
UUID = b"direct-test-pair"
IPV6 = socket.inet_pton(socket.AF_INET6, "2001:db8::19") + (36011).to_bytes(2, "little")


def run(server, relay, strict):
    port = int(os.environ.get("RUSTDESK_TEST_DIRECT_PORT", 32316)) + (0 if strict else 20)
    endpoint = ("127.0.0.1", port)
    controlled = ("127.0.0.3", 0)
    controller = ("127.0.0.2", 0)
    with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
        work = Path(temp)
        # Both daemons load the project's .env aliases before their first request.
        (work / ".env").write_text("direct-only=" + ("Y" if strict else "N") + "\n")
        env = dict(os.environ, TEST_HBBS="no", ALWAYS_USE_RELAY="N", MASK="")
        for binary, listen in ((server, port), (relay, port + 1)):
            process = subprocess.Popen([binary, "-p", str(listen)], cwd=work, env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(process.wait, 8)
            stack.callback(process.terminate)
            key = wait_for_server(work, (endpoint[0], listen)).read_bytes().strip()
        public = base64.b64decode(key)
        peer = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        peer.settimeout(4)
        peer.bind(controlled)
        peer.connect(endpoint)
        peer.send(field(15, field(1, PEER) + field(2, b"direct-test-peer") + field(3, bytes(range(32)))))
        assert parse(parse(peer.recv(2048))[16]).get(1, 0) == 0
        peer.send(field(6, field(1, PEER) + field(3, 1) + field(4, 1)))
        assert not parse(parse(peer.recv(2048))[7]).get(2)
        request = field(1, PEER) + field(3, key) + field(6, VERSION)
        direct = request + field(40, 1) + field(10, IPV6)
        relay_request = field(1, PEER) + field(2, UUID) + field(4, RELAY) + field(6, key)

        def tcp(source=controller):
            return socket.create_connection(endpoint, 4, source)

        if strict:
            with tcp() as client:
                send_tcp(client, field(8, request))
                assert read_tcp(client, 11)[7] == REQUIRED
            with tcp() as client:
                secure = SecureConnection(client, public)
                secure.send(8, request + field(12, description("offer", b"12")[0]))
                assert secure.read(11)[7] == REQUIRED
            for message, reply, reason in ((8, 11, 7), (18, 19, 6)):
                with closing(websocket.create_connection(f"ws://127.0.0.1:{port + 2}", timeout=4)) as ws:
                    ws.send_binary(field(message, request if message == 8 else relay_request))
                    assert parse(parse(ws.recv())[reply])[reason] == REQUIRED
            with tcp() as client:
                send_tcp(client, field(18, relay_request))
                assert read_tcp(client, 19)[6] == REQUIRED
            with socket.create_connection((relay_address(), port + 1), 4) as stream:
                try:
                    send_tcp(stream, field(18, relay_request))
                    assert stream.recv(1) == b""
                except ConnectionError:
                    pass
            try:
                ws = websocket.create_connection(f"ws://127.0.0.1:{port + 3}", timeout=4)
            except (ConnectionError, websocket.WebSocketConnectionClosedException):
                pass
            else:
                ws.close()
                raise AssertionError("direct-only hbbr accepted a WebSocket relay")
            expect_no_packet(peer)

        # An old answerer may still supply relay details. Only direct fields reach the controller.
        with tcp() as client:
            send_tcp(client, field(8, direct + field(30, 1)))
            fetch = parse(parse(peer.recv(2048))[12])
            assert fetch[40] and fetch[30] and fetch[3] == IPV6 and not fetch.get(2)
            with tcp(controlled) as responder:
                send_tcp(responder, field(19, field(1, fetch[1]) + field(2, UUID) + field(3, RELAY)
                                          + field(4, PEER) + field(7, VERSION) + field(10, IPV6)))
            reply = read_tcp(client, 19)
            assert reply[10] == IPV6 and reply[5] and not reply.get(2) and not reply.get(3)
        with tcp() as client:
            send_tcp(client, field(8, direct))
            punch = parse(parse(peer.recv(2048))[9])
            assert punch[40] and punch[7] == IPV6 and not punch.get(2)
            with tcp(controlled) as responder:
                send_tcp(responder, field(10, field(1, punch[1]) + field(2, PEER)
                                          + field(3, RELAY) + field(5, VERSION) + field(7, IPV6)))
            reply = read_tcp(client, 11)
            assert reply[1] and reply[2] and reply[11] == IPV6 and not reply.get(4)
        with tcp() as client:
            send_tcp(client, field(8, direct))
            punch = parse(parse(peer.recv(2048))[9])
            with tcp(controlled) as responder:
                send_tcp(responder, field(19, field(1, punch[1]) + field(2, UUID) + field(3, RELAY)))
            assert read_tcp(client, 19) == {6: UNAVAILABLE}

        with tcp() as client, tcp(controlled) as responder:
            secure = SecureConnection(client, public)
            relay_line = b"a=candidate:1 1 udp 1 192.0.2.20 45123 typ relay\r\n"
            for incompatible in (description("offer", b"12")[0],
                                 description("offer", b"12", "direct_only", relay_line)[0]):
                secure.send(8, direct + field(12, incompatible))
                assert secure.read(11)[7] == UNAVAILABLE
            offer, fingerprint = description("offer", b"12", "direct_only")
            secure.send(8, direct + field(7, 36010) + field(12, offer))
            punch = parse(parse(peer.recv(2048))[9])
            assert punch[40] and punch[10] == offer and len(punch[31]) == 16 and not punch.get(2)
            answer = description("answer", b"AB", "direct_only")[0]
            controlled_session = SecureConnection(responder, public)
            response = field(1, punch[1]) + field(4, PEER) + field(7, VERSION)
            controlled_session.send(19, response + field(12, description("answer", b"AB")[0]))
            expect_no_packet(client)
            controlled_session.send(19, response + field(10, IPV6))
            ipv6_only = secure.read(19)
            assert ipv6_only[10] == IPV6 and ipv6_only[5] and not ipv6_only.get(2) and not ipv6_only.get(3)
            relay_ice = b'{"candidate":"candidate:1 1 udp 1 192.0.2.20 45123 typ relay"}'
            secure.send(29, field(1, PEER) + field(3, fingerprint) + field(4, relay_ice))
            expect_no_packet(peer)
            direct_ice = relay_ice.replace(b"typ relay", b"typ srflx")
            secure.send(29, field(1, PEER) + field(3, fingerprint) + field(4, direct_ice))
            assert parse(parse(peer.recv(2048))[29])[4] == direct_ice
            controlled_session.send(19, field(1, punch[1]) + field(2, UUID) + field(3, RELAY)
                                    + field(4, PEER) + field(7, VERSION) + field(12, answer))
            reply = secure.read(19)
            assert reply[12] == answer and reply[5] and not reply.get(2) and not reply.get(3)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(controlled)
                udp.sendto(field(10, field(1, punch[1]) + field(2, PEER) + field(3, RELAY)
                                 + field(5, VERSION) + field(31, punch[31])), endpoint)
            reply = secure.read(11)
            assert reply[9] and not reply.get(4)
            secure.send(18, relay_request)
            assert secure.read(19) == {6: REQUIRED}
        print(f"Passed IPv6, LAN, TCP, UDP, secure signaling and relay suppression (DIRECT_ONLY={strict})")


if __name__ == "__main__":
    for strict in (False, True):
        run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), strict)
