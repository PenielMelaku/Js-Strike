#!/usr/bin/env python3
"""Simple HTTP server to serve test fixtures for JS Strike testing."""

import http.server
import os
import sys
import threading
import time

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_fixtures")
PORT = 8777


class FixtureHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FIXTURE_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/scripts/config.js":
            config_path = os.path.join(FIXTURE_DIR, "scripts", "config.js")
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Synthesize dummy test tokens at runtime so literal patterns aren't stored in git
            replacements = {
                "__STRIPE_LIVE_KEY_PLACEHOLDER__": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
                "__SLACK_WEBHOOK_PLACEHOLDER__": "https://hooks.slack.com/" + "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "__SLACK_TOKEN_PLACEHOLDER__": "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
            }
            for placeholder, value in replacements.items():
                content = content.replace(placeholder, value)
            data = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        super().do_GET()

    def log_message(self, format, *args):
        pass  # Suppress request logging


def start_server(port=PORT):
    """Start the fixture server in a background thread. Returns (server, thread)."""
    server = http.server.HTTPServer(("127.0.0.1", port), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)  # Give it a moment to bind
    return server, thread


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print(f"Serving test fixtures from {FIXTURE_DIR} on http://127.0.0.1:{port}")
    server = http.server.HTTPServer(("127.0.0.1", port), FixtureHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()

