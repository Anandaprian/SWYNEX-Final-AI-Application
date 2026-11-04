"""
PII Guard API server — Task 4 backend
SWYNEX Internship · Browser Extension project

Endpoints
---------
GET  /health   -> {"status": "ok", ...}          (used by the popup status dot)
POST /redact   -> {"redacted_text": "...", ...}  (used by the extension)

Design decisions
----------------
* The pii_guard engine is imported at module load, so spaCy + Presidio load
  ONCE at startup — every request afterwards is fast (Loophole 4).
* Binds to 127.0.0.1 ONLY: the API is reachable from this machine and not
  from the local network.
* A global lock serialises engine calls: spaCy pipelines are NOT thread-safe,
  and Flask's dev server is multi-threaded (prevents concurrent crashes).
* Fail-closed contract: if this server is down, the extension BLOCKS the
  send (it never lets unscanned text through).
* Never logs raw message text — only entity counts/types.
* PORT env var overrides the default 5000 (macOS AirPlay listens on 5000).

Run:  python server.py
"""
import os
import threading

from flask import Flask, jsonify, request
from flask_cors import CORS

import pii_guard  # heavy import — loads spaCy + Presidio once (Loophole 4)

app = Flask(__name__)
CORS(app)  # Loophole 3: let the extension (and local test pages) call this API

ENGINE_LOCK = threading.Lock()   # spaCy is not thread-safe — serialise calls
MAX_BODY_CHARS = 50_000          # abuse cap; the engine chunks internally anyway


@app.get("/health")
def health():
    """Liveness probe for the popup's status dot."""
    return jsonify({
        "status": "ok",
        "engine": "pii_guard",
        "model": "spaCy (loaded at startup)",
        "endpoints": ["/health", "/redact"],
    })


@app.post("/redact")
def redact():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
        return jsonify({"error": 'Send JSON body: {"text": "..."}'}), 400

    text = payload["text"]
    if len(text) > MAX_BODY_CHARS:
        return jsonify({"error": f"Text too long (max {MAX_BODY_CHARS} chars)."}), 413

    resume_mode = bool(payload.get("resume_mode", False))

    with ENGINE_LOCK:  # one spaCy call at a time
        report = pii_guard.protect_pii(text, verbose=False, resume_mode=resume_mode)

    if report["output"] is None:
        # Engine refused to process (empty input, or fail-closed failure)
        return jsonify({
            "error": report["error"] or "Engine failed to process text.",
            "risk_level": report["risk_level"],
        }), 422

    return jsonify({
        "redacted_text": report["output"],
        "entities": report["entities"],
        "risk_score": report["risk_score"],
        "risk_level": report["risk_level"],
        "redaction_count": report.get("redaction_count", 0),
        "degraded": bool(report["error"]),          # true => regex fallback was used
        "error": report["error"],                   # informational in degraded mode
        "resume_mode": report["resume_mode"],
        "chunked": report.get("chunked", False),
        "chunks": report.get("chunks", 1),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print("=" * 62)
    print(" PII Guard API — Task 4 backend")
    print(f"   POST http://127.0.0.1:{port}/redact   {{\"text\": \"...\"}}")
    print(f"   GET  http://127.0.0.1:{port}/health")
    print(" Fail-closed policy: if this server is unreachable, the")
    print(" extension BLOCKS sending — nothing leaks unscanned.")
    print(" Tip: PORT=5001 python server.py  (macOS AirPlay uses 5000)")
    print("=" * 62)
    app.run(host="127.0.0.1", port=port, threaded=True)
