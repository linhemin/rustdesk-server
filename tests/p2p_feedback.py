"""Start a fresh hbbs and verify signed, aggregate-only feedback and relay policy."""
import base64
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from p2p_signaling import SecureConnection, field, send_tcp, wait_for_server


def command(port, text):
    with socket.create_connection(("127.0.0.1", port - 1), 2) as client:
        client.sendall(text.encode())
        return client.recv(4096).decode()


def run(binary, enabled):
    port = 32266
    endpoint = ("127.0.0.1", port)
    config = dict(os.environ, P2P_FEEDBACK="Y" if enabled else "N",
                  RELAY_ISP_ROUTES='[{"left":"192.0.2.0/24","right":"198.51.100.0/24","relays":["127.0.0.1:32432"]}]')
    config["RELAY-SERVERS"] = "127.0.0.1:32431,127.0.0.1:32432"
    with tempfile.TemporaryDirectory(prefix="rustdesk-p2p-feedback-") as name:
        directory = Path(name)
        config["DB_URL"] = str(directory / "db_v2.sqlite3")
        with (directory / "hbbs.log").open("w+b") as log:
            server = subprocess.Popen([binary, "-p", str(port)], cwd=directory,
                                      env=config, stdout=log, stderr=log)
            try:
                public_key = base64.b64decode(wait_for_server(directory, endpoint).read_bytes())
                counts = (1, 1, 0, 3, 0, 1, 0, 0, 1)
                sample = b"".join(field(i + 1, n) for i, n in enumerate((1, 1, 1, 9420, 224, 250, 553)))
                sample += b"".join(field(8, count) for count in counts)
                with socket.create_connection(endpoint, 4) as plain:
                    send_tcp(plain, field(30, sample))
                    assert plain.recv(1) == b""
                for report in (sample + field(5, 501), sample):
                    with socket.create_connection(endpoint, 4) as conn:
                        peer = SecureConnection(conn, public_key)
                        assert peer.allow_p2p_feedback == enabled
                        peer.send(30, report)
                        assert conn.recv(1) == b""
                if not enabled:
                    assert command(port, "p2p-metrics") == "P2P feedback disabled\n"
                    return
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    request = b"\x00\x01\x00\x18\x21\x12\xa4\x42abcdefgh1234\x80\x22\x00\x14RustDesk observation"
                    client.sendto(request, endpoint)
                    packet, sender = client.recvfrom(512)
                    assert sender == endpoint and packet[:2] == b"\x01\x01"
                    assert packet[4:20] == request[4:20]
                summary_line, seed_line = command(port, "p2p-metrics").splitlines()
                summary = dict(entry.split("=") for entry in summary_line.split())
                assert all(summary[key] == value for key, value in {
                    "full_ready": "1", "full_failed": "0", "local_candidates": "224",
                    "peer_candidates": "250", "observer_ipv4": "1", "observer_replied": "1",
                }.items()), summary
                assert seed_line.endswith(str(list(counts))), seed_line
                assert "127.0.0.1:32432" in command(port, "tg 198.51.100.1 192.0.2.1")
                print("Signed report aggregated once, plain and oversize reports excluded, observer counters and ISP relay policy verified.")
            finally:
                server.terminate()
                server.wait(timeout=8)


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    run(binary, False)
    run(binary, True)
