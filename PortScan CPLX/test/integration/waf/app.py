from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(403)
        self.send_header("Content-type", "text/html")
        self.send_header("X-Sucuri-ID", "1")
        self.send_header("Server", "test-waf")
        self.end_headers()
        self.wfile.write(b"Attention required - checking your browser before accessing")

if __name__ == "__main__":
    server_address = ("0.0.0.0", 80)
    HTTPServer(server_address, Handler).serve_forever()
