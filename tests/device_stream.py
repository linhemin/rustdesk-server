"""Check TCP/WSS-backend control registration, relay signalling and disconnection on a real hbbs."""
import base64
from contextlib import closing, contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from nacl.bindings import crypto_secretbox_open
from nacl.signing import SigningKey, VerifyKey
import websocket
from local_wss import LocalWss

from p2p_signaling import SecureConnection, field, parse, read_frame, read_tcp, send_tcp, wait_for_server

ID = b"318450672"
ENDPOINT = ("127.0.0.1", 32462)
HOST = ("127.0.0.3", 0)
DOMAIN = b"RustDesk registered control stream v1\0"


@contextmanager
def hbbs(binary, root):
    with (root / "hbbs.log").open("ab") as log:
        server = subprocess.Popen([binary, "-b", ENDPOINT[0], "-p", str(ENDPOINT[1])], cwd=root,
                                  stdout=log, stderr=log, env=dict(os.environ, DB_URL=str(root / "db.sqlite3")))
        try:
            yield wait_for_server(root, ENDPOINT).read_bytes().strip()
        finally:
            server.terminate()
            server.wait(5)


@contextmanager
def device(mode, operator, tls):
    if mode == "wss":
        with tls.connect((ENDPOINT[0], ENDPOINT[1] + 2), "/ws/id") as conn:
            yield conn.send_binary, conn.recv
    elif mode == "ws":
        addr = (ENDPOINT[0], ENDPOINT[1] + 2)
        with closing(websocket.create_connection(f"ws://{addr[0]}:{addr[1]}/", timeout=2,
                                                 socket=socket.create_connection(addr, 2, HOST))) as conn:
            yield conn.send_binary, conn.recv
    else:
        with socket.create_connection(ENDPOINT, 2, HOST) as conn:
            secured = SecureConnection(conn, operator)
            def send(packet):
                if packet:
                    [(number, contents)] = parse(packet).items()
                    secured.send(number, contents)
                else:
                    send_tcp(conn, b"")
            def recv():
                frame = read_frame(conn)
                return crypto_secretbox_open(frame, secured.nonce("receive"), secured.keys["receive"]) if frame else frame
            yield send, recv


def prove(send, recv, device_key, operator, identity=ID, replay=None):
    public = bytes(device_key.verify_key)
    nonce = os.urandom(32)
    send(field(15, field(1, identity) + field(2, b"opaque-device-uuid") + field(3, public)
               + field(46, nonce) + field(47, 1)))
    challenge = parse(parse(recv())[33])
    tail = operator + public + nonce + challenge[1] + identity
    VerifyKey(operator).verify(DOMAIN + b"\x01" + tail, challenge[2])
    proof = field(33, field(2, device_key.sign(DOMAIN + b"\x00" + tail).signature))
    send(replay or proof)
    return proof


def run(binary):
    device_key = SigningKey.generate()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with hbbs(binary, root):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(HOST)
                udp.settimeout(2)
                udp.connect(ENDPOINT)
                udp.send(field(15, field(1, ID) + field(2, b"opaque-device-uuid") + field(3, bytes(device_key.verify_key))))
                assert parse(parse(udp.recv(2048))[16]).get(1, 0) == 0
        # Restart clears UDP presence, while the enrolled public key survives in SQLite.
        with hbbs(binary, root) as key:
            operator = base64.b64decode(key)
            tls = LocalWss(root)
            for mode in ("tcp", "ws", "wss"):
                with device(mode, operator, tls) as (send, recv):
                    proof = prove(send, recv, device_key, operator)
                    assert parse(parse(recv())[16])[2] == 12
                    assert recv() == b""
                    send(b"")
                    with socket.create_connection(ENDPOINT, 2, ("127.0.0.2", 0)) as requester:
                        send_tcp(requester, field(8, field(1, ID) + field(3, key) + field(6, b"1.5.3")))
                        offer = parse(parse(recv())[9])
                        with socket.create_connection(ENDPOINT, 2, HOST) as reply:
                            send_tcp(reply, field(10, field(1, offer[1]) + field(2, ID) + field(5, b"1.5.3")))
                        assert len(read_tcp(requester, 11)[2]) > 64
                    with socket.create_connection(ENDPOINT, 2, ("127.0.0.2", 0)) as requester:
                        accepted = b"wss://custom.example/ws/relay"
                        listing = field(47, field(1, accepted))
                        send_tcp(requester, field(18, field(1, ID) + field(2, b"device-test") + listing))
                        pending = parse(parse(recv())[18])
                        assert parse(pending[47])[1] == accepted
                        with socket.create_connection(ENDPOINT, 2, HOST) as reply:
                            send_tcp(reply, field(19, field(1, pending[3]) + field(2, b"device-test")
                                                  + field(3, accepted) + listing))
                        assert read_tcp(requester, 19)[3] == accepted
                with device(mode, operator, tls) as (send, recv):
                    prove(send, recv, device_key, operator, replay=proof)
                    try:
                        assert not recv(), "a previous connection's proof was accepted"
                    except (EOFError, websocket.WebSocketConnectionClosedException):
                        pass
                for identity, supplied in ((ID, SigningKey.generate()), (b"420184516", SigningKey.generate())):
                    with device(mode, operator, tls) as (send, recv):
                        prove(send, recv, supplied, operator, identity=identity)
                        try:
                            assert not recv(), "an unenrolled key was allowed to bind a device"
                        except (EOFError, websocket.WebSocketConnectionClosedException):
                            pass
                with socket.create_connection(ENDPOINT, 2, ("127.0.0.2", 0)) as caller:
                    send_tcp(caller, field(8, field(1, ID) + field(3, key)))
                    assert read_tcp(caller, 11).get(3) == 2, "stale control link still advertised online"
    print("TCP and WebSocket control streams passed device ownership, heartbeat, punch delivery, offline and replay tests.")


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()))
