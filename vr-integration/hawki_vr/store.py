"""Durable requests, component outcomes, and atomic dispatch claims."""
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .catalog import Invalid, digest

LIVE = {"queued", "submitting", "submitted", "cancel_requested"}


class Store:
    def __init__(self, path=None):
        self.path = Path(path or os.getenv("HAWKI_VR_DB", "/app/data/velociraptor/workspace.sqlite3"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY, actor TEXT NOT NULL, idem TEXT NOT NULL,
              input_hash TEXT NOT NULL, manifest TEXT NOT NULL, state TEXT NOT NULL,
              created REAL NOT NULL, expires REAL NOT NULL, approver TEXT,
              hunt_id TEXT, hunt_state TEXT NOT NULL DEFAULT 'none', error TEXT,
              UNIQUE(actor, idem));
            CREATE TABLE IF NOT EXISTS units (
              id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, client_id TEXT NOT NULL,
              artifact TEXT NOT NULL, state TEXT NOT NULL, flow_id TEXT,
              error TEXT, native TEXT, linked INTEGER NOT NULL DEFAULT 0,
              updated REAL NOT NULL,
              UNIQUE(job_id, client_id, artifact));
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY, job_id TEXT, time REAL NOT NULL,
              event TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS heartbeat (id INTEGER PRIMARY KEY CHECK(id=1),
              time REAL NOT NULL, ready INTEGER NOT NULL, reason TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def event(db, job, kind, actor, detail=None):
        db.execute("INSERT INTO events(job_id,time,event,actor,detail) VALUES(?,?,?,?,?)", (job,time.time(),kind,str(actor),json.dumps(detail or {},ensure_ascii=False)))

    def draft(self, actor, idem, inputs, manifest):
        if not isinstance(idem, str) or not 16 <= len(idem) <= 100 or not idem.isascii():
            raise Invalid("요청 식별자가 필요합니다.")
        with self.connect(True) as db:
            old = db.execute("SELECT * FROM jobs WHERE actor=? AND idem=?", (actor,idem)).fetchone()
            if old:
                if old["input_hash"] != digest(inputs):
                    raise Invalid("같은 요청 식별자로 내용을 변경할 수 없습니다.")
                return old["id"]
            n = db.execute("SELECT COUNT(*) FROM jobs WHERE state IN ('draft','pending_approval','queued','active')").fetchone()[0]
            if n >= 100:
                raise Invalid("진행 중인 요청이 너무 많습니다.")
            job = "VR-" + secrets.token_hex(8).upper()
            now = time.time()
            db.execute("INSERT INTO jobs(id,actor,idem,input_hash,manifest,state,created,expires) VALUES(?,?,?,?,?,'draft',?,?)", (job,actor,idem,digest(inputs),json.dumps(manifest,ensure_ascii=False),now,now+3600))
            self.event(db, job, "draft_created", actor)
            return job

    def get(self, job):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            if not row:
                raise Invalid("수집 요청을 찾을 수 없습니다.")
            result = dict(row)
            result["manifest"] = json.loads(result["manifest"])
            result.pop("idem", None); result.pop("input_hash", None)
            result["units"] = [dict(x) for x in db.execute("SELECT * FROM units WHERE job_id=? ORDER BY id", (job,))]
            for u in result["units"]:
                u["native"] = json.loads(u["native"]) if u["native"] else None
            result["events"] = [dict(x) for x in db.execute("SELECT * FROM events WHERE job_id=? ORDER BY id", (job,))]
            return result

    def list(self, offset=0, client_id=""):
        with self.connect() as db:
            where = "WHERE state != 'draft'"
            values = []
            if client_id:
                where += " AND EXISTS (SELECT 1 FROM json_each(jobs.manifest,'$.client_ids') WHERE value=?)"
                values.append(client_id)
            ids = [r[0] for r in db.execute(f"SELECT id FROM jobs {where} ORDER BY created DESC LIMIT 51 OFFSET ?", (*values,offset))]
        return dict(items=[self.get(i) for i in ids[:50]], has_more=len(ids)>50, offset=offset)

    def submit(self, job, actor):
        with self.connect(True) as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            if not row or row["actor"] != actor:
                raise Invalid("요청 작성자만 제출할 수 있습니다.")
            if row["state"] != "draft":
                return
            if row["expires"] < time.time():
                raise Invalid("요청이 만료되었습니다. 다시 검토하세요.")
            m = json.loads(row["manifest"])
            state = "pending_approval" if m["approval_required"] else "queued"
            db.execute("UPDATE jobs SET state=? WHERE id=?", (state,job))
            for client in m["client_ids"]:
                for artifact in m["spec"]:
                    db.execute("INSERT INTO units(job_id,client_id,artifact,state,updated) VALUES(?,?,?,'queued',?)", (job,client,artifact,time.time()))
            self.event(db, job, state, actor)

    def decide(self, job, actor, approve):
        with self.connect(True) as db:
            r = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            if not r or r["state"] != "pending_approval" or r["expires"] < time.time():
                raise Invalid("승인 가능한 요청이 아닙니다.")
            state = "queued" if approve else "rejected"
            db.execute("UPDATE jobs SET state=?,approver=? WHERE id=?", (state,actor,job))
            if not approve:
                db.execute("UPDATE units SET state='rejected' WHERE job_id=? AND state='queued'", (job,))
            self.event(db, job, "approved" if approve else "rejected", actor)

    def cancel(self, job, actor):
        with self.connect(True) as db:
            row = db.execute("SELECT state FROM jobs WHERE id=?", (job,)).fetchone()
            if not row:
                raise Invalid("요청을 찾을 수 없습니다.")
            db.execute("UPDATE jobs SET state='cancel_requested' WHERE id=? AND state NOT IN ('finished','failed','rejected','cancelled')", (job,))
            db.execute("UPDATE units SET state='cancelled',updated=? WHERE job_id=? AND state='queued'", (time.time(),job))
            db.execute("UPDATE units SET state='cancel_requested',updated=? WHERE job_id=? AND state='submitted'", (time.time(),job))
            self.event(db, job, "cancel_requested", actor)

    def beat(self, ready, reason=""):
        with self.connect(True) as db:
            db.execute("INSERT OR REPLACE INTO heartbeat VALUES(1,?,?,?)", (time.time(),int(ready),reason))

    def health(self):
        with self.connect() as db:
            r = db.execute("SELECT * FROM heartbeat WHERE id=1").fetchone()
            return dict(ready=bool(r and r["ready"] and time.time()-r["time"] < 90), checked_at=r["time"] if r else None)

    def recover(self):
        # Interrupted submissions are not retried: the server may have accepted them.
        with self.connect(True) as db:
            db.execute("UPDATE units SET state='submission_unknown',error='worker_interrupted' WHERE state='submitting'")
            db.execute("UPDATE jobs SET hunt_state='unknown',error='worker_interrupted' WHERE hunt_state='submitting'")

    def claim(self):
        with self.connect(True) as db:
            db.execute("UPDATE jobs SET state='expired' WHERE state IN ('draft','pending_approval','queued') AND expires < ?", (time.time(),))
            # Limit active endpoint work. A disconnected endpoint cannot accumulate an
            # unbounded queue. No urgent submissions.
            if db.execute("SELECT COUNT(*) FROM units WHERE state IN ('submitted','submitting','cancel_requested')").fetchone()[0] >= 6:
                return None
            r = db.execute("""SELECT u.* FROM units u JOIN jobs j ON j.id=u.job_id
                WHERE u.state='queued' AND j.state IN ('queued','active') AND j.expires>?
                AND j.hunt_state NOT IN ('unknown','submitting')
                AND NOT EXISTS(SELECT 1 FROM units x WHERE x.job_id=j.id AND x.state='submission_unknown')
                AND (SELECT COUNT(*) FROM units y WHERE y.client_id=u.client_id AND y.state IN ('submitted','submitting','cancel_requested')) < 2
                ORDER BY u.id LIMIT 1""", (time.time(),)).fetchone()
            if not r:
                return None
            db.execute("UPDATE units SET state='submitting',updated=? WHERE id=? AND state='queued'", (time.time(),r["id"]))
            db.execute("UPDATE jobs SET state='active' WHERE id=?", (r["job_id"],))
            self.event(db,r["job_id"],"dispatch_claimed","worker",dict(unit_id=r["id"]))
            return dict(r)

    def unit(self, unit_id, **changes):
        allowed = {"state","flow_id","error","native","linked"}
        if not changes or set(changes)-allowed:
            raise ValueError("Invalid update")
        if "native" in changes:
            changes["native"] = json.dumps(changes["native"],ensure_ascii=False)
        changes["updated"] = time.time()
        with self.connect(True) as db:
            db.execute("UPDATE units SET "+",".join(k+"=?" for k in changes)+" WHERE id=?", (*changes.values(),unit_id))
            job = db.execute("SELECT job_id FROM units WHERE id=?", (unit_id,)).fetchone()[0]
            self.event(db,job,"component_updated","worker",dict(unit_id=unit_id,**{k:v for k,v in changes.items() if k!="native"}))

    def finish_jobs(self):
        with self.connect(True) as db:
            for r in db.execute("SELECT id,state,expires,hunt_state FROM jobs WHERE state IN ('active','queued','cancel_requested')").fetchall():
                if r["expires"] < time.time():
                    db.execute("UPDATE units SET state='expired' WHERE job_id=? AND state='queued'", (r["id"],))
                states = {x[0] for x in db.execute("SELECT state FROM units WHERE job_id=?",(r["id"],))}
                if "submission_unknown" in states or r["hunt_state"] == "unknown":
                    state = "submission_unknown"
                elif states & LIVE:
                    continue
                elif states == {"finished"}:
                    state = "finished"
                elif states <= {"cancelled","expired"}:
                    state = "cancelled" if "cancelled" in states else "expired"
                else:
                    state = "partial" if "finished" in states else "failed"
                db.execute("UPDATE jobs SET state=? WHERE id=?",(state,r["id"]))
                self.event(db,r["id"],state,"worker")
