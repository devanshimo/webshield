from http.server import BaseHTTPRequestHandler, HTTPServer


class TestServer(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)

        # Intentionally weak cookie
        self.send_header(
            "Set-Cookie",
            "sessionid=abc123"
        )

        # Intentionally exposed technology
        self.send_header(
            "Server",
            "TestServer/1.0"
        )

        self.send_header(
            "Content-Type",
            "text/html"
        )

        self.end_headers()

        self.wfile.write(
            b"""
            <html>
                <head>
                    <title>WebShield Test Server</title>
                </head>
                <body>
                    <h1>Intentionally Insecure Test Page</h1>
                </body>
            </html>
            """
        )


server = HTTPServer(("127.0.0.1", 8766), TestServer)

print("Test server running at http://127.0.0.1:8766")

server.serve_forever()