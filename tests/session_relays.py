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


def node_id(endpoint, public, rendezvous_public):
    if public == rendezvous_public:
        return endpoint
    digest = sha256(b"RustDesk relay identity v1\0" + endpoint + b"\0" + public).hexdigest()[:48]
    return b"k1-" + digest.encode() + b".relay-id.invalid:21117"


def exercise_node_keys(hbbs, host, peer_id, operator, caller_bind, host_bind, bind, hbbr, launch, tls):
    default_pk = base64.b64decode(operator, validate=True)
    assert node_id(b"relay.example:21117", bytes(range(32)), bytes(32)) == (
        b"k1-1eaab4e6f29d823f5ac07387f620bfe396f10b5e2b71fe81.relay-id.invalid:21117")
    host.send(field(6, field(1, peer_id) + field(47, 1)))
    assert not parse(parse(host.recv(4096))[7]).get(2)
    local = {}
    for n, port in enumerate((32478, 32482)):
        public = bytes(SigningKey.generate().verify_key)
        address = f"{bind}:{port}".encode()
        wire = node_id(address, public, default_pk)
        launch(hbbr, f"independent-{n}", "-b", bind, "-p", str(port), "-k", base64.b64encode(public).decode())
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection((bind, port), .25):
                    break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.03)
        local[wire] = (address, port, public)

    ids = list(local)
    assert len(ids) == 2
    first, second = (local[i] for i in ids)
    assert node_id(first[0], default_pk, default_pk) == first[0]
    wrong_key = node_id(first[0], second[2], default_pk)
    assert wrong_key not in local
    # Eight entries exceed the UDP budget. Membership of either keyed node survives compaction.
    long_names = [(b"d" * 60 + b".") * 3 + str(i).encode() + b".test:21117" for i in range(6)]
    for offer, selected, approved in [(ids, ids[0], True), (long_names + ids, ids[1], True),
                                      (ids, wrong_key, False), (ids, first[0], False),
                                      ([first[0]], ids[0], False)]:
        with socket.create_connection(hbbs, 4, caller_bind) as caller:
            sample = field(41, field(1, selected) + field(2, 25))
            send_tcp(caller, field(8, field(1, peer_id) + field(3, operator) + field(6, b"1.5.3") + listing(offer) + sample))
            punch = parse(parse(host.recv(4096))[9])
            relays = parse_fields(punch[47])
            if len(offer) == 8:
                assert relays[2] == [b"".join(sha256(i).digest()[:16] for i in offer)]
            else:
                assert relays[1] == offer
                assert (parse(punch[41])[1] if 41 in punch else None) == (selected if approved else None)
            with socket.create_connection(hbbs, 4, host_bind) as reply:
                send_tcp(reply, field(10, field(1, punch[1]) + field(2, peer_id) + field(3, selected)
                                      + field(5, b"1.5.3") + listing([selected])))
            result = read_tcp(caller, 11)
            if not approved:
                assert result.get(4, b"") == b"" and result[47] == b""
                continue
            assert result[4] == selected and parse_fields(result[47])[1] == [selected]
            # The identifier never reaches the resolver: the dial and credentials come from
            # the test peer's own entry, as they must for a client using the 147 wire protocol.
            _, port, public = local[result[4]]
            pair_id = uuid.uuid4().hex.encode()
            with socket.create_connection(hbbs, 4, caller_bind) as requester:
                send_tcp(requester, field(18, field(1, peer_id) + field(2, pair_id) + field(4, selected) + listing([selected])))
                pending = parse(parse(host.recv(4096))[18])
                assert pending[2] == pair_id and pending[4] == selected and parse(pending[47])[1] == selected
                with socket.create_connection(hbbs, 4, host_bind) as responder:
                    send_tcp(responder, field(19, field(1, pending[3]) + field(2, pending[2]) + field(3, selected) + listing([selected])))
                ack = read_tcp(requester, 19)
                assert ack[2] == pair_id and ack[3] == selected and parse(ack[47])[1] == selected
            request = field(2, ack[2])
            for bad in (default_pk, second[2] if public == first[2] else first[2]):
                with socket.create_connection((bind, port), 4) as wrong:
                    send_tcp(wrong, field(18, request + field(6, base64.b64encode(bad))))
                    assert wrong.recv(1) == b""
            pair = field(18, request + field(6, base64.b64encode(public)))
            with socket.create_connection((bind, port), 4) as left, socket.create_connection((bind, port), 4) as right:
                send_tcp(left, pair)
                send_tcp(right, pair)
                left.sendall(b"to host")
                assert read_exact(right, 7) == b"to host"
                right.sendall(b"to caller")
                assert read_exact(left, 9) == b"to caller"
            ws_target = (bind, port + 2)
            with tls.connect(ws_target, "/ws/relay") as wrong:
                wrong.send_binary(field(18, request + field(6, operator)))
                try:
                    assert not wrong.recv()
                except websocket.WebSocketConnectionClosedException:
                    pass
            with tls.connect(ws_target, "/ws/relay") as left, tls.connect(ws_target, "/ws/relay") as right:
                left.send_binary(pair)
                right.send_binary(pair)
                left.send_binary(b"to host")
                assert right.recv() == b"to host"
                right.send_binary(b"to caller")
                assert left.recv() == b"to caller"
    print("Unchanged hbbs: endpoint/key agreement, compact wire IDs and two separately keyed hbbr pairs passed.")


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
