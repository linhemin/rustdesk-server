import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from nacl.bindings import (
    crypto_box,
    crypto_box_keypair,
    crypto_secretbox,
    crypto_secretbox_open,
    crypto_sign_open,
)


def varint(value):
    data = bytearray()
    while value > 127:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def read_varint(data, offset):
    value = shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
        shift += 7
    raise ValueError("truncated varint")


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def parse_fields(data):
    values = defaultdict(list)
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        number, kind = tag >> 3, tag & 7
        value, offset = read_varint(data, offset)
        if kind == 2:
            values[number].append(data[offset:offset + value])
            offset += value
        elif kind == 0:
            values[number].append(value)
        else:
            raise ValueError(f"unexpected wire type {kind}")
    return values


def parse(data):
    return {number: values[-1] for number, values in parse_fields(data).items()}


def send_tcp(connection, data):
    width = 1 if len(data) <= 63 else 2
    connection.sendall(((len(data) << 2) | (width - 1)).to_bytes(width, "little") + data)


def read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected TCP close")
        data.extend(chunk)
    return bytes(data)


def read_tcp(connection, message):
    while True:
        payload = parse(read_frame(connection))
        if message in payload:
            return parse(payload[message])


def read_frame(connection):
    first = read_exact(connection, 1)
    header = first + read_exact(connection, first[0] & 3)
    return read_exact(connection, int.from_bytes(header, "little") >> 2)


class SecureConnection:
    """Use the RustDesk 1.5.3 wire format independently of the server implementation."""

    def __init__(self, connection, public_key):
        self.connection = connection
        self.nonces = {"send": 0, "receive": 0}
        hello = parse(read_frame(connection))
        assert set(hello) == {25}
        exchange = parse(hello[25])
        assert exchange[2] == 1
        server_key = crypto_sign_open(exchange[1], public_key)
        assert len(server_key) == 32 and server_key[-1] & 0x80
        params = crypto_sign_open(exchange[3], public_key)
        assert params.startswith(b"rdkx-params")
        assert parse(params[len(b"rdkx-params"):]) == {1: server_key, 2: 1}
        public, private = crypto_box_keypair()
        master = os.urandom(32)
        encrypted = crypto_box(master, bytes(24), server_key, private)
        send_tcp(connection, field(25, field(1, public) + field(1, encrypted) + field(2, 1)))
        transcript = b"\x01\x00\x00\x00" * 2 + public + server_key
        self.keys = {
            direction: hashlib.blake2b(
                b"rdkx-spl" + bytes([role]) + transcript, key=master, digest_size=32
            ).digest()
            for direction, role in (("send", 1), ("receive", 2))
        }

    def nonce(self, direction):
        self.nonces[direction] += 1
        return self.nonces[direction].to_bytes(24, "little")

    def send(self, number, data):
        payload = field(number, data)
        send_tcp(self.connection, crypto_secretbox(payload, self.nonce("send"), self.keys["send"]))

    def read(self, number):
        ciphertext = read_frame(self.connection)
        payload = crypto_secretbox_open(ciphertext, self.nonce("receive"), self.keys["receive"])
        return parse(parse(payload)[number])


def description(kind, byte):
    fingerprint = b"sha-256 " + b":".join([byte] * 32)
    sdp = b"v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:" + fingerprint + b"\r\n"
    return b"webrtc://" + base64.b64encode(json.dumps(
        {"type": kind, "sdp": sdp.decode(), "ice_policy": "all"}
    ).encode()), fingerprint


def expect_no_packet(sock):
    original = sock.gettimeout()
    sock.settimeout(0.25)
    try:
        assert not sock.recv(4096), "unexpected forwarded packet"
    except socket.timeout:
        pass
    finally:
        sock.settimeout(original)


def relay_address():
    # hbbr reserves source loopback addresses for its administrative socket.
    if address := os.environ.get("RUSTDESK_TEST_RELAY_HOST"):
        return address
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        return route.getsockname()[0]


def encode_address(address, port):
    stamp = int(time.time() * 1_000_000) & 0xFFFFFFFF
    ip = int.from_bytes(socket.inet_aton(address), "little")
    encoded = ((ip + stamp) << 49) | (stamp << 17) | (port + (stamp & 0xFFFF))
    return encoded.to_bytes(16, "little").rstrip(b"\x00")


def test(workspace):
    port = 32216
    endpoint = ("127.0.0.1", port)
    controller = ("127.0.0.2", 0)
    controlled = ("127.0.0.3", 0)
    peer_id = b"324165901"
    version = b"1.5.3"
    key = workspace.joinpath("id_ed25519.pub")
    deadline = time.monotonic() + 8
    while not key.exists():
        assert time.monotonic() < deadline, "server did not generate test keys"
        time.sleep(0.05)
    while True:
        try:
            with socket.create_connection(endpoint, 0.2):
                break
        except ConnectionRefusedError:
            assert time.monotonic() < deadline, "server did not listen"
            time.sleep(0.05)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mediator:
        mediator.settimeout(4)
        mediator.bind(controlled)
        mediator.connect(endpoint)
        mediator.send(field(15, field(1, peer_id) + field(2, b"test-lan-client") + field(3, bytes(range(32)))))
        assert parse(parse(mediator.recv(2048))[16]).get(1, 0) == 0

        def register(supports_lan):
            registration = field(1, peer_id)
            if supports_lan:
                registration += field(3, 1)
            mediator.send(field(6, registration))
            assert not parse(parse(mediator.recv(2048))[7]).get(2)

        def request(connection, supports_lan):
            payload = field(1, peer_id) + field(3, key.read_bytes().strip()) + field(6, version)
            if supports_lan:
                payload += field(30, 1)
            send_tcp(connection, field(8, payload))

        register(True)
        with socket.create_connection(endpoint, 4, controller) as requester:
            request(requester, True)
            fetch = parse(parse(mediator.recv(2048))[12])
            assert fetch[30] == 1
            listener = encode_address("0.0.0.0", 32190)
            acknowledgement = (
                field(1, fetch[1]) + field(2, listener) + field(4, peer_id)
                + field(5, version) + field(30, 1)
            )
            with socket.create_connection(endpoint, 4, controlled) as response:
                send_tcp(response, field(13, acknowledgement))
            reply = read_tcp(requester, 11)
            assert reply[30] == 1 and reply[6] == 1
            assert reply[1] == listener and len(reply[2]) > 64
        print("Confirmed LAN coordination across distinct source addresses and signed peer identity")

        register(False)
        with socket.create_connection(endpoint, 4, controller) as requester:
            request(requester, True)
            assert read_tcp(requester, 11)[7] == b"LAN probe unavailable"
        with socket.create_connection(endpoint, 4, controller) as requester:
            request(requester, False)
            assert 9 in parse(mediator.recv(2048))
        print("Confirmed capability opt-out and unmodified TCP punch request routing")

        with socket.create_connection(endpoint, 4, controlled) as requester:
            request(requester, False)
            fetch = parse(parse(mediator.recv(2048))[12])
            assert not fetch.get(30)
            listener = encode_address("192.168.50.10", 32191)
            acknowledgement = (
                field(1, fetch[1]) + field(2, listener) + field(4, peer_id) + field(5, version)
            )
            with socket.create_connection(endpoint, 4, controlled) as response:
                send_tcp(response, field(13, acknowledgement))
            reply = read_tcp(requester, 11)
            assert not reply.get(30)
            assert reply[6] == 1 and reply[1] == listener and len(reply[2]) > 64
        print("Confirmed stock controller receives the same-egress LAN address and signed key")

        public_key = base64.b64decode(key.read_bytes())
        offer, fingerprint = description("offer", b"12")
        answer, _ = description("answer", b"AB")
        req = field(1, peer_id) + field(3, key.read_bytes().strip()) + field(12, offer)
        candidate = b'{"candidate":"candidate:1 1 udp 1 192.0.2.10 41234 typ host"}'
        ice = field(3, fingerprint) + field(4, candidate)

        # A legacy/plain request still works, but it must not carry an SDP offer.
        with socket.create_connection(endpoint, 4, controller) as connection:
            send_tcp(connection, field(8, req))
            assert 10 not in parse(parse(mediator.recv(2048))[9])
            send_tcp(connection, field(29, field(1, peer_id) + ice))
            expect_no_packet(mediator)

        with socket.create_connection(endpoint, 4, controller) as connection:
            phone = SecureConnection(connection, public_key)
            phone.send(8, req)
            forwarded = parse(parse(mediator.recv(2048))[9])
            assert forwarded[10] == offer
            route = field(2, forwarded[1])
            phone.send(29, field(1, b"unrelated-peer") + ice)
            phone.send(29, field(1, peer_id) + ice)
            assert parse(parse(mediator.recv(2048))[29]) == {3: fingerprint, 4: candidate}
            expect_no_packet(mediator)

            with socket.create_connection(endpoint, 4, ("127.0.0.4", 0)) as response:
                unrelated = SecureConnection(response, public_key)
                unrelated.send(29, route + ice)
                expect_no_packet(connection)
            with socket.create_connection(endpoint, 4, controlled) as response:
                windows = SecureConnection(response, public_key)
                windows.send(29, route + field(3, b"wrong session") + field(4, candidate))
                windows.send(29, route + ice)
                assert phone.read(29) == {3: fingerprint, 4: candidate}
                windows.send(10, field(1, forwarded[1]) + field(2, peer_id)
                             + field(5, version) + field(8, answer))
                reply = phone.read(11)
                assert reply[12] == answer
                assert parse(crypto_sign_open(reply[2], public_key))[1] == peer_id

        print("Confirmed signed v1 key exchange and scoped SDP/ICE delivery in both directions")

        # Exercise the Windows symmetric-NAT branch, where the answer rides beside the relay UUID.
        with socket.create_connection(endpoint, 4, controller) as connection:
            phone = SecureConnection(connection, public_key)
            phone.send(8, req + field(2, 2))
            punch = parse(parse(mediator.recv(2048))[9])
            relay_id = b"e0642844-85b1-4ca8-9bbb-af277182f5ee"
            relay_request = field(18, field(2, relay_id) + field(6, key.read_bytes().strip()))
            relay_endpoint = (relay_address(), 32217)
            with socket.create_connection(endpoint, 4, controlled) as response:
                windows = SecureConnection(response, public_key)
                windows.send(19, field(1, punch[1]) + field(2, relay_id)
                             + field(3, b"127.0.0.1:32217") + field(4, peer_id)
                             + field(7, version) + field(12, answer))
                reply = phone.read(19)
                assert reply[2] == relay_id and reply[12] == answer
                assert parse(crypto_sign_open(reply[5], public_key))[1] == peer_id
            with socket.create_connection(relay_endpoint, 4) as one, \
                    socket.create_connection(relay_endpoint, 4) as two:
                send_tcp(one, relay_request)
                # The controlled side has sent its request before the controller receives
                # RelayResponse. Stagger the test sockets to reproduce that ordering.
                time.sleep(0.15)
                send_tcp(two, relay_request)
                payload = b"relay transport smoke payload"
                one.sendall(payload)
                assert read_exact(two, len(payload)) == payload

        print("Confirmed relay answer carries the SDP and hbbr can pair/forward when ICE is unavailable")


def main():
    server = Path(sys.argv[1]).resolve()
    relay = Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="rustdesk-p2p-smoke-") as temp:
        workspace = Path(temp)
        with workspace.joinpath("hbbs.log").open("w+") as log:
            process = subprocess.Popen([server, "-p", "32216"], cwd=workspace, stdout=log, stderr=log)
            relay_process = subprocess.Popen(
                [relay, "-p", "32217"], cwd=workspace, stdout=log, stderr=log
            )
            try:
                test(workspace)
            except Exception:
                log.seek(0)
                for line in log:
                    if "Key:" not in line and "public key" not in line:
                        print(line.rstrip(), file=sys.stderr)
                raise
            finally:
                process.terminate()
                relay_process.terminate()
                process.wait(timeout=8)
                relay_process.wait(timeout=8)


if __name__ == "__main__":
    main()
