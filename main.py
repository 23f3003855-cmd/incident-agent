"""Observable incident triage agent (ga5-incident-agent/v2).

Stdlib only. Layers are kept separate:
  planner  -> one Gemini call per new runId (diagnosis, diagnostics, effect)
  machine  -> receipt-driven state machine (retry, timeout, approval, effect)
  trace    -> OTLP + logs built purely from stored dispatches / receipts
Replays and GET read stored JSON; they never call the model.

Debug helpers (metadata only, no incident content):
  GET /_log   recent request / planner events
  GET /_test  tiny live test of every configured model
"""
import collections
import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

PROFILE = "ga5-incident-agent/v2"
# If a Render persistent disk is mounted at /var/data, use it automatically.
# Free instances without a disk keep using /tmp; set DB_PATH explicitly for other hosts.
_DEFAULT_DB_PATH = "/var/data/incident.db" if os.path.isdir("/var/data") else "/tmp/incident.db"
DB_PATH = os.environ.get("DB_PATH", _DEFAULT_DB_PATH)
if DB_PATH != ":memory:":
    _db_dir = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(_db_dir, exist_ok=True)
MAX_BODY = 6 * 1024 * 1024
PLAN_BUDGET = float(os.environ.get("PLAN_BUDGET", "13.5"))  # keep below the grader's 18s request limit

# Prefer the model verified as working in the deployed logs, even if Render still
# has an older GEMINI_MODELS ordering. Other configured models remain fallbacks.
def configured_models():
    preferred = os.environ.get("GEMINI_PRIMARY_MODEL", "gemini-3.1-flash-lite").strip()
    configured = [m.strip() for m in os.environ.get(
        "GEMINI_MODELS",
        "gemini-3.1-flash-lite,gemini-3.5-flash-lite,gemini-3-flash-preview"
    ).split(",") if m.strip()]
    # Put low-cost fallbacks ahead of old configured entries; the logs showed
    # gemini-3.5-flash returning 429 quota errors. It remains a last-resort model.
    candidates = [preferred, "gemini-3.5-flash-lite", "gemini-3.6-flash",
                  "gemini-3-flash-preview"] + configured
    seen, result = set(), []
    for name in candidates:
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


MODELS = configured_models()

_events = collections.deque(maxlen=300)


def log(*a):
    line = "%s %s" % (time.strftime("%H:%M:%S"), " ".join(str(x) for x in a))
    _events.append(line)
    print(line, flush=True)


# ---------------------------------------------------------------- helpers
def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(o):
    s = o if isinstance(o, str) else canon(o)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def nes(x, maxlen=512):
    return isinstance(x, str) and 0 < len(x.strip()) and len(x) <= maxlen


def now_ns():
    return time.time_ns()


class HttpError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


# ---------------------------------------------------------------- storage
_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_db.execute("PRAGMA journal_mode=WAL")
_db.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, req_hash TEXT, state TEXT)")
_db.execute("CREATE TABLE IF NOT EXISTS receipts (run_id TEXT, receipt_id TEXT, hash TEXT, "
