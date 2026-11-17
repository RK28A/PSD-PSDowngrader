import http.server, os, random, socket, ssl, sys

SIZE = 10 * 1024 * 1024
DROP = 3 * 1024 * 1024
rnd = random.Random(42)
DATA = b"SLB2" + rnd.randbytes(SIZE - 4)


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts = {}

    def log_message(self, *a):
        pass

    def simple(self, code, ctype=b"text/plain", body=b"x", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype.decode())
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        name = self.path.rsplit("/", 1)[-1]
        if name == "redirect.PUP":
            return self.simple(302, extra={"Location": "https://evil.example.com/x.PUP"})
        if name == "missing.PUP":
            return self.simple(404)
        if name == "html.PUP":
            return self.simple(200, b"text/html", b"<html>captcha</html>")
        n = H.counts.get(name, 0)
        H.counts[name] = n + 1
        etag = '"v2"' if name == "changing.PUP" and n >= 1 else '"v1"'
        start, status = 0, 200
        rng, ifr = self.headers.get("Range"), self.headers.get("If-Range")
        if rng and (ifr is None or ifr == etag):
            start, status = int(rng.split("=")[1].split("-")[0]), 206
        body = DATA[start:]
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", etag)
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{SIZE - 1}/{SIZE}")
        self.end_headers()
        limit = DROP if name in ("flaky.PUP", "changing.PUP") else len(body)
        sent = 0
        while sent < len(body):
            chunk = body[sent:sent + 65536]
            if sent + len(chunk) > limit:
                self.wfile.write(chunk[: limit - sent])
                self.wfile.flush()
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            self.wfile.write(chunk)
            sent += len(chunk)


if __name__ == "__main__":
    cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("ready", flush=True)
    srv.serve_forever()
