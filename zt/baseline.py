"""Plain HTTP server with NO identity, NO encryption and NO policy: the 'before' picture for the benchmark."""
import json
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .common import HOST, PORTS

PAYLOAD = json.dumps({'value': 'x' * 2000}).encode()      # ~2 KB body, like the report's benchmark


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    wbufsize = 65536
    disable_nagle_algorithm = True

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = HOST, self.server_address[1]


if __name__ == '__main__':
    Server((HOST, PORTS['baseline']), Handler).serve_forever()
