        raw, model, source = run_planner(safe_body, ptext, ev_ids, effect_tools, catalog, max_diag, ctx["idents"][:40])
        t_plan1 = now_ns()
        plan = normalize_plan(raw, body, transcript, ev_ids, effect_tools, catalog, max_diag, secrets, sig, ctx)
        log("plan run=%s model=%s cause_ok=%s evidence=%s diags=%s effect=%s approval_req=%s incoming_tp=%s" % (
            rid[:12], model, plan["diagnosis"]["rootCause"] in inc["allowedRootCauses"],
            plan["diagnosis"]["evidence"], [d["toolName"] for d in plan["diagnostics"]],
            plan["effect"]["toolName"] if plan["effect"] else None,
            plan["effect"]["toolName"] in policy.get("approvalRequiredFor", []) if plan["effect"] else None,
            bool(parse_tp(hdrs.get("traceparent")) or parse_tp(body.get("traceparent")))))
        st, new = init_state(body, plan, model, hdrs, t_start, t_plan0, t_plan1)
        st["_secrets"] = secrets  # Private database state; never part of a response/trace.
        checked_response(st, new)
        db_save(rid, sha(body), st)
        log("run created", rid[:12], "diag=%d" % len(st["diagIds"]), "approval=%s" % st["needsApproval"])
        return checked_response(st, new)


def handle_receipt(run_id, body):
    if not isinstance(body, dict) or not nes(body.get("receiptId"), 256):
        raise HttpError(422, "invalid receipt")
    with run_lock(run_id):
        row = db_get_run(run_id)
        if not row:
            raise HttpError(404, "unknown run")
        req_hash, st = row
        rid, h = body["receiptId"], sha(body)
        prev = db_get_receipt(run_id, rid)
        if prev:
            if prev[0] == h:
                log("receipt replay", run_id[:12])
                return prev[1]
            raise HttpError(409, "receiptId reused with different content")
        log("receipt in", run_id[:12], "outcomes=%d approvals=%d" % (
            len(body.get("outcomes") or []) if isinstance(body.get("outcomes"), list) else 0,
            len(body.get("approvals") or []) if isinstance(body.get("approvals"), list) else 0))
        new = apply_receipt(st, body)
        resp = checked_response(st, new)
        db_save(run_id, req_hash, st, (rid, h, resp))
        log("receipt", run_id[:12], "status=%s" % st["status"], "new=%d" % len(new))
        return resp


def get_run(run_id):
    row = db_get_run(run_id)
    if not row:
        raise HttpError(404, "unknown run")
    return checked_response(row[1])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, text, ctype="application/json; charset=utf-8"):
        pth = self._path()
        if pth != "/" and not pth.startswith("/_"):
            log("%s %s -> %d" % (self.command, pth[:70], code))
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _err(self, code, msg):
        self._send(code, dumps({"error": msg}))

    def _path(self):
        return self.path.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"

    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise HttpError(400, "bad length")
        if n < 0:
            raise HttpError(400, "bad length")
        if n > MAX_BODY:
            raise HttpError(413, "too large")
        raw = self.rfile.read(n) if n else b""
        try:
            return json.loads(raw.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError("non-finite JSON")))
        except Exception:
            raise HttpError(400, "invalid json")

    def do_GET(self):
        try:
            p = self._path()
            if p == "/":
                return self._send(200, dumps({"ok": True, "profile": PROFILE}))
            m = re.match(r"^/v2/incidents/([^/]+)$", p)
            if m:
                return self._send(200, get_run(unquote(m.group(1))))
            self._err(404, "not found")
        except HttpError as e:
            log("reject", self.command, self._path()[:60], e.code, e.msg[:80])
            self._err(e.code, e.msg)
        except Exception as e:
            log("GET error", type(e).__name__)
            self._err(500, "internal error")

    def do_POST(self):
        try:
            p = self._path()
            if p == "/v2/incidents":
                body = self._json_body()
                hdrs = {"traceparent": self.headers.get("traceparent"),
                        "tracestate": self.headers.get("tracestate")}
                return self._send(200, create_run(body, hdrs))
            m = re.match(r"^/v2/incidents/([^/]+)/receipts$", p)
            if m:
                body = self._json_body()
                return self._send(200, handle_receipt(unquote(m.group(1)), body))
            self._err(404, "not found")
        except HttpError as e:
            log("reject", self.command, self._path()[:60], e.code, e.msg[:80])
            self._err(e.code, e.msg)
        except Exception as e:
            log("POST error", type(e).__name__)
            self._err(500, "internal error")


def main():
    port = int(os.environ.get("PORT", "10000"))
    log("starting on", port, "models", ",".join(MODELS), "db", DB_PATH)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
