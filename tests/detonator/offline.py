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

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/fixtures/pages")
http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None  # type: ignore[method-assign]
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8000), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
page = sys.argv[1]
print(json.dumps(detonate.run(f"http://127.0.0.1:8000/{page}", None)))
