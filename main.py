"""Observable incident triage agent (ga5-incident-agent/v2).

Stdlib only. Layers are kept separate:
  planner  -> one Gemini call per new runId (diagnosis, diagnostics, effect)
  machine  -> receipt-driven state machine (retry, timeout, approval, effect)
  trace    -> OTLP built purely from stored dispatches / receipts
Replays and GET read stored JSON; they never call the model.

Env vars:
  GEMINI_API_KEY (or GOOGLE_API_KEY)   required for real planning
  GEMINI_PRIMARY_MODEL, GEMINI_MODELS  optional model overrides
  DB_PATH                              optional sqlite path
  PORT                                 listen port (Render sets this)

Debug endpoints are disabled; logs contain only operational metadata.
Use a persistent disk for DB_PATH and a single server process.
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
_DEFAULT_DB_PATH = "/var/data/incident.db" if os.path.isdir("/var/data") else "/tmp/incident.db"
DB_PATH = os.environ.get("DB_PATH", _DEFAULT_DB_PATH)
if DB_PATH != ":memory:":
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
MAX_BODY = 6 * 1024 * 1024
PLAN_BUDGET = float(os.environ.get("PLAN_BUDGET", "13.5"))  # grader allows 18s per request
REVERSAL_TOOLS = ("rollback_deployment", "disable_feature")


def configured_models():
    # Set this explicitly to a model enabled for your API key.
    return [os.environ.get("GEMINI_PRIMARY_MODEL", "gemini-3.1-flash-lite").strip()]


MODELS = configured_models()
_events = collections.deque(maxlen=400)
_last = collections.deque(maxlen=12)
_transcripts = collections.deque(maxlen=10)


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


def rand_hex(nbytes):
    while True:
        h = os.urandom(nbytes).hex()
        if int(h, 16) != 0:
            return h


class HttpError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


TP_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def parse_tp(s):
    if not isinstance(s, str):
        return None
    m = TP_RE.match(s.strip())
    if not m or m.group(1) == "ff" or int(m.group(2), 16) == 0 or int(m.group(3), 16) == 0:
        return None
