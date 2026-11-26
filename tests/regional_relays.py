"""Exercise directory discovery and relay selection with one local hbbs and three hbbr processes."""
import base64
from contextlib import ExitStack, closing
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import uuid

from nacl.bindings import crypto_secretbox_open
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
import websocket
from local_wss import LocalWss

from p2p_signaling import (SecureConnection, description, expect_no_packet, field, parse, parse_fields, read_exact, read_frame,
                           read_tcp, relay_address, send_tcp, wait_for_server)


def run(hbbs, hbbr):
    host = relay_address()
    ports = [32442, 32446, 32450]
    names = [f"{host}:{port}".encode() for port in ports]
    endpoint = ("127.0.0.1", 32436)
    nonce = b"12345678"

    with tempfile.TemporaryDirectory() as state, ExitStack() as stack:
        def launch(binary, name, *args):
            directory = Path(state, name)
            directory.mkdir()
            log = stack.enter_context((directory / "server.log").open("wb"))
            server = subprocess.Popen([binary, *args], cwd=directory, stdout=log, stderr=log,
                                      env=dict(os.environ, DB_URL=str(directory / "db_v2.sqlite3")))
            stack.callback(server.wait, 5)
            stack.callback(server.terminate)
            return directory

        directory = launch(hbbs, "hbbs", "-b", endpoint[0], "-p", str(endpoint[1]), "-r", b",".join(names).decode())
        key = wait_for_server(directory, endpoint).read_bytes().strip()
        public = base64.b64decode(key)
        for i, port in enumerate(ports):
            launch(hbbr, f"hbbr-{i}", "-b", host, "-p", str(port), "-k", key.decode())
        with socket.create_connection(endpoint, 3) as conn:
            send_tcp(conn, field(31, b""))
            assert conn.recv(1) == b"", "unauthenticated TCP exposed a relay directory"
        with socket.create_connection(endpoint, 3) as conn:
            session = SecureConnection(conn, public)
            session.send(31, b"")
            msg = crypto_secretbox_open(read_frame(conn), session.nonce("receive"), session.keys["receive"])
            assert parse_fields(parse(msg)[31])[1] == names

        def ws(addr, port):
            return closing(websocket.create_connection(f"ws://{addr}:{port}/", timeout=3,
                                                       socket=socket.create_connection((addr, port), 3)))

        tls = LocalWss(Path(state))
        ws_backend = (endpoint[0], endpoint[1] + 2)
        try:
            with tls.connect(ws_backend, "/ws/id", trusted=False):
                raise AssertionError("a private test CA was accepted without trust")
        except ssl.SSLCertVerificationError:
            pass
        with tls.connect(ws_backend, "/ws/id") as signaling:
            challenge = b"\x11" + nonce
            signaling.send_binary(field(31, challenge))
            directory = parse(signaling.recv())[31]
            expected = b"".join(field(1, name) for name in names) + challenge
            assert directory.startswith(expected)
            fields = parse(directory[len(expected):])
            assert fields[4] == 1
            verifier = VerifyKey(public)
            domain = b"RustDesk regional relay directory v1\0"
            verifier.verify(domain + expected + field(4, 1), fields[3])
            try:
                verifier.verify(domain + expected, fields[3])
            except BadSignatureError:
                pass
            else:
                raise AssertionError("WebSocket permission could be changed without invalidating the signature")

        ping = field(32, b"\x09" + nonce)
        for port in ports:
            with socket.create_connection((host, port), 3) as relay:
                send_tcp(relay, ping)
                assert read_frame(relay) == ping
                assert relay.recv(1) == b""
            with ws(host, port + 2) as relay:
                relay.send_binary(ping)
                assert relay.recv() == ping
            with tls.connect((host, port + 2), "/ws/relay") as relay:
                relay.send_binary(ping)
                assert relay.recv() == ping

        peer_id = b"123456789"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(("127.0.0.3", 0))
            peer.connect(endpoint)
            peer.settimeout(3)
            peer.send(field(15, field(1, peer_id) + field(2, b"test-regions") + field(3, bytes(range(32)))))
            assert parse(parse(peer.recv(2048))[16]).get(1, 0) == 0
            peer.send(field(6, field(1, peer_id)))
            assert not parse(parse(peer.recv(2048))[7]).get(2)
            def sample(name, ms):
                return field(41, field(1, name) + field(2, ms))

            for winner in (2, 1):
                request = field(1, peer_id) + field(3, key) + field(6, b"1.5.3")
                request += field(43, 1)
                request += sample(b"arbitrary.invalid:9999", 1) + sample(names[0], 150) + sample(names[winner], 8)
                with socket.create_connection(endpoint, 3, ("127.0.0.2", 0)) as caller:
                    send_tcp(caller, field(8, request))
                    offer = parse_fields(parse(peer.recv(2048))[9])
                    assert offer[43] == [1]
                    assert offer[2] == [names[winner]] and [parse(s)[1] for s in offer[41]] == [names[winner], names[0]]
                    with socket.create_connection(endpoint, 3, ("127.0.0.3", 0)) as reply:
                        send_tcp(reply, field(10, field(1, offer[1][0]) + field(2, peer_id)
                                              + field(3, names[winner]) + field(5, b"1.5.3")))
                    assert read_tcp(caller, 11)[4] == names[winner]
                pair = field(18, field(2, uuid.uuid4().hex.encode()) + field(6, key))
                with socket.create_connection((host, ports[winner]), 3) as caller, \
                        socket.create_connection((host, ports[winner]), 3) as responder:
                    send_tcp(caller, pair)
                    send_tcp(responder, pair)
                    caller.sendall(b"left")
                    assert read_exact(responder, 4) == b"left"
                    responder.sendall(b"right")
                    assert read_exact(caller, 5) == b"right"
            with socket.create_connection(endpoint, 3, ("127.0.0.2", 0)) as caller, \
                    socket.create_connection(endpoint, 3, ("127.0.0.3", 0)) as responder:
                start = SecureConnection(caller, public)
                reply = SecureConnection(responder, public)
                sdp, _ = description("offer", b"AC")
                start.send(8, field(1, peer_id) + field(3, key) + field(6, b"1.5.3")
                           + field(12, sdp) + field(43, 1))
                offer = parse(parse(peer.recv(2048))[9])
                assert offer[43] == 1 and len(offer[45]) == 16
                ack = (field(1, offer[1]) + field(2, b"startup-session") + field(3, offer[2])
                       + field(4, peer_id) + field(7, b"1.5.3") + field(43, 1))
                reply.send(19, ack + field(45, bytes(16)))
                expect_no_packet(caller)
                reply.send(19, ack + field(45, offer[45]))
                receipt = start.read(19)
                assert receipt[43] == 1 and len(receipt[5]) > 64 and not receipt.get(45)
                reply.send(19, ack + field(45, offer[45]))
                expect_no_packet(caller)
            from session_relays import exercise
            exercise(endpoint, peer, peer_id, key, ("127.0.0.2", 0), ("127.0.0.3", 0))
            from session_relays import exercise_node_keys
            exercise_node_keys(endpoint, peer, peer_id, key, ("127.0.0.2", 0), ("127.0.0.3", 0),
                               host, hbbr, launch, tls)
    print("Three independent hbbr processes: signed discovery, TCP/WS echo, per-session selection and bidirectional payload passed.")


if __name__ == "__main__":
    run(*(str(Path(arg).resolve()) for arg in sys.argv[1:]))
