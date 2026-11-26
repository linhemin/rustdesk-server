"""TLS termination for the loopback hbbs/hbbr integration tests. No system roots are modified."""
from contextlib import closing, contextmanager
import socket
import ssl
import subprocess
from threading import Thread

import websocket


class LocalWss:
    def __init__(self, directory):
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=directory, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Local Test CA",
                "-keyout", "ca.key", "-out", "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "tls.key", "-out", "tls.csr")
        (directory / "tls.ext").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\n")
        openssl("x509", "-req", "-days", "1", "-in", "tls.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-extfile", "tls.ext", "-out", "tls.pem")
        self.client = ssl.create_default_context(cafile=directory / "ca.pem")
        self.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.load_cert_chain(directory / "tls.pem", directory / "tls.key")

    @contextmanager
    def connect(self, target, path, trusted=True):
        def pump(source, output):
            try:
                while data := source.recv(16384):
                    output.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    output.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)

            def terminate():
                raw = listener.accept()[0]
                try:
                    with self.server.wrap_socket(raw, server_side=True) as tls, socket.create_connection(target, 3) as backend:
                        upload = Thread(target=pump, args=(tls, backend), daemon=True)
                        upload.start()
                        pump(backend, tls)
                except OSError:
                    pass

            worker = Thread(target=terminate, daemon=True)
            worker.start()
            try:
                validation = self.client if trusted else ssl.create_default_context()
                with socket.create_connection(listener.getsockname(), 3) as raw, \
                        validation.wrap_socket(raw, server_hostname="localhost") as tls, \
                        closing(websocket.create_connection(f"wss://localhost{path}", socket=tls, timeout=3)) as ws:
                    yield ws
            finally:
                worker.join(5)
