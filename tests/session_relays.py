"""Explicit relay lists with registered peers using real hbbs TCP and UDP frames."""
from hashlib import sha256
import base64
import socket
import time
import uuid

from nacl.signing import SigningKey
import websocket

from p2p_signaling import field, parse, parse_fields, read_exact, read_tcp, send_tcp


def listing(names):
    return field(47, b"".join(field(1, name) for name in names))


def exercise(endpoint, host, peer_id, key, caller_bind, host_bind):
    first = b"relay-a.example:21117"
    second = b"relay-b.example:21117"
    third = b"relay-c.example:21117"
    request = field(1, peer_id) + field(3, key) + field(6, b"1.5.3")
    reg = field(1, peer_id)

    def capability(enabled):
        host.send(field(6, reg + (field(47, 1) if enabled else b"")))
        assert not parse(parse(host.recv(4096))[7]).get(2)

    def offer(names):
        caller = socket.create_connection(endpoint, 5, caller_bind)
        try:
            send_tcp(caller, field(8, request + listing(names)))
            packet = parse(host.recv(8192))
            kind = 9 if 9 in packet else 12
            return caller, kind, parse(packet[kind])
        except BaseException:
            caller.close()
            raise

    def answer(kind, offer, names, selected):
        if kind == 9:
            n, body = 10, field(1, offer[1]) + field(2, peer_id) + field(5, b"1.5.3")
        else:
            n, body = 13, field(1, offer[1]) + field(2, b"\x02\x01") + field(4, peer_id) + field(5, b"1.5.3")
        with socket.create_connection(endpoint, 5, host_bind) as reply:
            send_tcp(reply, field(n, body + listing(names) + field(3, selected)))

    capability(True)
    for names, reply_names, choice, allowed in [
        ([first, second], [third, second], second, [second]),
        ([first, second], [third], third, []),
        ([], [third], third, []),
        ([first] * 9, [first], first, []),
    ]:
        caller, kind, msg = offer(names)
        with caller:
            assert not msg.get(2) and 47 in msg
            assert parse_fields(msg[47]).get(1, []) == (names if len(names) <= 8 else [])
            answer(kind, msg, reply_names, choice)
            ack = read_tcp(caller, 11)
            assert parse_fields(ack[47]).get(1, []) == allowed
            assert ack.get(4, b"") == (choice if choice in allowed else b"")

    large = [(b"a" * 62 + b".") * 3 + str(i).encode() + b".test:21117" for i in range(8)]
    caller, kind, msg = offer(large)
    with caller:
        assert parse(msg[47]) == {2: b"".join(sha256(s).digest()[:16] for s in large)}
        answer(kind, msg, [large[-1]], large[-1])
        assert read_tcp(caller, 11)[4] == large[-1]

    for supports, names, proposed, accept in [
        (True, [first, second], second, True), (True, [first], third, False),
        (True, [], b"", False), (False, [first], first, False),
    ]:
        capability(supports)
        with socket.create_connection(endpoint, 5, caller_bind) as caller:
            uuid = b"relay-list-test"
            req = field(1, peer_id) + field(2, uuid) + field(4, proposed) + listing(names)
            send_tcp(caller, field(18, req))
            if accept:
                pending = parse(parse(host.recv(4096))[18])
                assert parse_fields(pending[47])[1] == names
                with socket.create_connection(endpoint, 5, host_bind) as reply:
                    send_tcp(reply, field(19, field(1, pending[3]) + field(2, uuid)
                                         + field(3, second) + listing([second])))
            ack = read_tcp(caller, 19)
            if accept:
                assert ack[2] == uuid and ack[3] == second and parse_fields(ack[47])[1] == [second]
            else:
                assert ack[6] and not ack.get(3)

    caller, kind, msg = offer([first, second])
    with caller:
        assert msg.get(40) == 1 and msg[47] == b"" and not msg.get(2)
        answer(kind, msg, [], third)
        assert not read_tcp(caller, 11).get(4)
    print("Session lists: overlap, no overlap, empty, long UDP offers, relay requests and legacy host passed.")
