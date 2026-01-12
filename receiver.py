from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        print("\n🔔 ALERT RECEIVED:")
        print(json.dumps(json.loads(body), indent=2))
        self.send_response(200)
        self.end_headers()

HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
