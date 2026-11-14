"""Inside the detonator container, for the tests only (D1): serve the fixture pages on loopback and
open one with the real detonate.run. The test container has no network at all (--network none), so
no proxy is used; everything else (user, sandbox, limits) is as in production."""

import functools
import http.server
import json
import sys
import threading

sys.path.insert(0, "/opt/detonator")
import detonate  # noqa: E402


class Pages(http.server.SimpleHTTPRequestHandler):
    """The fixture pages; cloak.html is refused to anything that is not a phone, as some kits do."""

    def do_GET(self) -> None:  # noqa: N802  (the name http.server calls)
        if self.path.startswith("/cloak") and "iPhone" not in self.headers.get("User-Agent", ""):
            self.send_error(403)
            return
        super().do_GET()

    def log_message(self, *args: object) -> None:
        pass


handler = functools.partial(Pages, directory="/fixtures/pages")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8000), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
page = sys.argv[1]
print(json.dumps(detonate.run(f"http://127.0.0.1:8000/{page}", None)))
