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

# A protobuf int32 below zero is encoded as a sign-extended, 64-bit varint.
SESSION_DIRECT_PROOF = (1 << 64) - 604180


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
        signed_params = parse(params[len(b"rdkx-params"):])
        assert signed_params[1] == server_key and signed_params[2] == 1
        self.allow_session_direct = signed_params.get(3, 0)
        self.allow_p2p_feedback = signed_params.get(5, 0)
        # This fixture uses a single documentation address; it is never contacted.
        if os.environ.get("TEST_SIGNED_OBSERVER"):
            assert signed_params.get(4) == (b"192.0.2.17:32216" if self.allow_session_direct else None)
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


def description(kind, byte, policy="all", candidate=b""):
    fingerprint = b"sha-256 " + b":".join([byte] * 32)
    sdp = b"v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:" + fingerprint + b"\r\n"
    return b"webrtc://" + base64.b64encode(json.dumps(
        {"type": kind, "sdp": (sdp + candidate).decode(), "ice_policy": policy}
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


def wait_for_server(workspace, endpoint):
    key = workspace.joinpath("id_ed25519.pub")
    deadline = time.monotonic() + 8
    while not key.exists():
        assert time.monotonic() < deadline, "server did not generate test keys"
        time.sleep(0.05)
    while True:
        try:
            with socket.create_connection(endpoint, 0.2):
                break
        except (ConnectionRefusedError, socket.timeout):
            assert time.monotonic() < deadline, "server did not listen"
            time.sleep(0.05)
    return key


def test(workspace):
    endpoint = ("127.0.0.1", 32216)
    controller = ("127.0.0.2", 0)
    controlled = ("127.0.0.3", 0)
    peer_id = b"324165901"
    version = b"1.5.3"
    key = wait_for_server(workspace, endpoint)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mediator:
        mediator.settimeout(4)
        mediator.bind(controlled)
        mediator.connect(endpoint)
        tid = os.urandom(12)
        cookie = bytes.fromhex("2112a442")
        software = b"RustDesk observation"
        query = b"\x00\x01\x00\x18" + cookie + tid + b"\x80\x22\x00\x14" + software
        mediator.send(query)
        response = mediator.recv(256)
        assert response[:8] == b"\x01\x01\x00\x0c" + cookie and response[8:20] == tid
        assert response[20:26] == b"\x00\x20\x00\x08\x00\x01"
        assert int.from_bytes(response[26:28], "big") ^ 0x2112 == mediator.getsockname()[1]
        assert bytes(a ^ b for a,b in zip(response[28:32],cookie)) == socket.inet_aton(controlled[0])
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

        with socket.create_connection(endpoint, 4, controller) as connection:
            # An ordinary, unsecured NAT test has neither an authenticated reply nor a reusable
            # connection, including if its caller happens to supply the reserved serial.
            send_tcp(connection, field(20, field(1, SESSION_DIRECT_PROOF)))
            assert read_tcp(connection, 21)[1] == connection.getsockname()[1]
            assert not connection.recv(1)

        public_key = base64.b64decode(key.read_bytes())
        with socket.create_connection(endpoint, 4, controlled) as requester:
            session = SecureConnection(requester, public_key)
            session.send(8, field(1, peer_id) + field(3, key.read_bytes().strip())
                         + field(6, version) + field(7, 32192) + field(40, 1))
            fetch = parse(parse(mediator.recv(2048))[12])
            assert fetch[40] == 1
            acknowledgement = field(1, fetch[1]) + field(2, listener) + field(4, peer_id) + field(5, version)
            with socket.create_connection(endpoint, 4, controlled) as response:
                send_tcp(response, field(13, acknowledgement))
            reply = session.read(11)
            assert reply[6] == 1 and reply[1] == listener and not reply.get(4)
            assert parse(crypto_sign_open(reply[2], public_key))[1] == peer_id
        print("Confirmed authenticated direct-only controller receives the same-egress LAN address")
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
            assert phone.allow_session_direct == 1
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

        mediator.send(field(6, field(1, peer_id) + field(4, 1)))
        assert not parse(parse(mediator.recv(2048))[7]).get(2)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as controller_udp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer_udp, \
                socket.create_connection(endpoint, 4, controller) as connection:
            controller_udp.bind(controller)
            controller_udp.settimeout(4)
            controller_udp.sendto(query, endpoint)
            mapped = controller_udp.recv(256)
            assert mapped[8:20] == tid
            port = int.from_bytes(mapped[26:28], "big") ^ 0x2112
            assert port == controller_udp.getsockname()[1]
            phone = SecureConnection(connection, public_key)
            phone.send(8, field(1, peer_id) + field(3, key.read_bytes().strip()) + field(7, port))
            punch = parse(parse(mediator.recv(2048))[9])
            assert punch[4] == port and len(punch[31]) == 16 and 10 not in punch
            peer_udp.bind(controlled)
            response = field(1, punch[1]) + field(2, peer_id) + field(5, version)
            peer_udp.sendto(field(10, response + field(31, b"wrong reply key!")), endpoint)
            expect_no_packet(connection)
            datagram = field(10, response + field(31, punch[31]))
            peer_udp.sendto(datagram, endpoint)
            reply = phone.read(11)
            encoded = int.from_bytes(reply[1], "little")
            stamp = (encoded >> 17) & 0xffffffff
            assert (((encoded & 0xffffff) - (stamp & 0xffff)) & 0xffff) == peer_udp.getsockname()[1]
            assert reply[9] == 1 and parse(crypto_sign_open(reply[2], public_key))[1] == peer_id
            peer_udp.sendto(datagram, endpoint)
            expect_no_packet(connection)
        print("Confirmed same-socket UDP observation and one-use authenticated KCP rendezvous")

        def observe_candidate(sock):
            query = bytearray(96)
            query[:8] = bytes.fromhex("0001004c2112a442")
            query[8:20] = os.urandom(12)
            query[20:32] = bytes.fromhex("00260048") + b"RD-PATH1"
            sock.sendto(query, endpoint)
            data, source = sock.recvfrom(128)
            assert source == endpoint and data[8:20] == query[8:20] and data[32:36] == bytes.fromhex("c0510026")
            return data[36:74]

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b, \
                socket.create_connection(endpoint, 4, controller) as connection:
            a.bind(controller)
            b.bind(controlled)
            a.settimeout(3)
            b.settimeout(3)
            left, right = observe_candidate(a), observe_candidate(b)
            session = SecureConnection(connection, public_key)
            session.send(8, field(1, peer_id) + field(3, key.read_bytes().strip())
                         + field(7, a.getsockname()[1]) + field(33, left) + field(40, 1))
            punch = parse(parse(mediator.recv(2048))[9])
            assert punch[33] == varint(a.getsockname()[1])
            response = field(1, punch[1]) + field(2, peer_id) + field(5, version)
            b.sendto(field(10, response + field(31, punch[31]) + field(33, right)), endpoint)
            reply = session.read(11)
            assert reply[9] and not reply.get(4) and reply[33] == varint(b.getsockname()[1])
            assert reply[34] == hashlib.sha256(punch[31]).digest()
        print("Confirmed strict, NAS-attested supplementary ports and scoped peer probe credential")

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
                windows.send(20, field(1, SESSION_DIRECT_PROOF))
                assert windows.read(21)[1] == response.getsockname()[1]
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


def test_restricted_policy(server, workspace, env, port):
    endpoint = ("127.0.0.1", port)
    with workspace.joinpath("policy.log").open("a") as log:
        process = subprocess.Popen([server, "-p", str(port)], cwd=workspace, env=env,
                                   stdout=log, stderr=log)
        try:
            key = wait_for_server(workspace, endpoint)
            with socket.create_connection(endpoint, 4) as connection:
                session = SecureConnection(connection, base64.b64decode(key.read_bytes()))
                assert session.allow_session_direct == 0
                session.send(20, field(1, SESSION_DIRECT_PROOF))
                assert session.read(21).get(1, 0) == 0
                session.send(20, b"")
                assert session.read(21)[1] == connection.getsockname()[1]
                assert not connection.recv(1)
        finally:
            process.terminate()
            process.wait(timeout=8)


def main():
    server = Path(sys.argv[1]).resolve()
    relay = Path(sys.argv[2]).resolve()
    with tempfile.TemporaryDirectory(prefix="rustdesk-p2p-smoke-") as temp:
        workspace = Path(temp)
        with workspace.joinpath("hbbs.log").open("w+") as log:
            os.environ["TEST_SIGNED_OBSERVER"] = "1"
            env = dict(os.environ, ALWAYS_USE_RELAY="N", MASK="", RUSTDESK_UDP_MAPPING_OBSERVERS="192.0.2.17:32216")
            process = subprocess.Popen([server, "-p", "32216"], cwd=workspace, env=env,
                                       stdout=log, stderr=log)
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
        test_restricted_policy(server, workspace, dict(env, ALWAYS_USE_RELAY="Y"), 32236)
        test_restricted_policy(server, workspace, dict(env, MASK="192.168.0.0/16"), 32246)
        print("Confirmed signed session-direct policy is disabled by forced relay or a LAN mask")


if __name__ == "__main__":
    main()
