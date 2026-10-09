"""Separate process holding the execution credential. No web server or shell RPC."""
import fcntl
import json
import os
import signal
import sys
import time
from pathlib import Path

from . import reader
from .catalog import FLOW, HUNT, Invalid
from .service import validate_dispatch
from .store import Store
from .transport import Transport, RemoteError, run

COLLECT = """
LET R <= collect_client(client_id=P.client_id, artifacts=P.artifacts,
  env=P.env, timeout=P.limits.timeout, cpu_limit=P.limits.cpu_limit,
  iops_limit=P.limits.iops_limit, max_rows=P.limits.max_rows,
  max_bytes=P.limits.max_bytes)
SELECT R AS result FROM scope()
"""
CREATE_HUNT = """
SELECT hunt(description=P.description, artifacts=P.artifacts, spec=P.spec,
  pause=TRUE, expires=now()+86400, include_labels=P.labels,
  timeout=P.limits.timeout, cpu_limit=P.limits.cpu_limit,
  iops_limit=P.limits.iops_limit, max_rows=P.limits.max_rows,
  max_bytes=P.limits.max_bytes) AS result FROM scope()
"""
LINK_HUNT = "SELECT hunt_add(hunt_id=P.hunt_id, client_id=P.client_id, flow_id=P.flow_id) AS result FROM scope()"
CANCEL = "SELECT cancel_flow(client_id=P.client_id, flow_id=P.flow_id) AS result FROM scope()"


def identifier(value, pattern):
    found=set()
    def walk(x):
        if isinstance(x,str) and pattern.fullmatch(x): found.add(x)
        elif isinstance(x,dict):
            for v in x.values(): walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(value)
    if len(found)!=1: raise RemoteError("missing_submission_id")
    return found.pop()


class Worker:
    def __init__(self,store,transport):
        self.db,self.t=store,transport

    def hunt(self, job):
        if not job["manifest"]["hunt"] or job["hunt_id"]:
            return job.get("hunt_id")
        if job["hunt_state"] not in {"none"}:
            raise RemoteError("hunt_submission_unknown")
        with self.db.connect(True) as conn:
            conn.execute("UPDATE jobs SET hunt_state='submitting' WHERE id=?",(job["id"],))
        m=job["manifest"]
        try:
            data=run(self.t,CREATE_HUNT,dict(description=f"HAW-KI {job['id']} · {m['label']} · {m['incident']}",artifacts=list(m["spec"]),spec=m["spec"],limits=m["limits"],labels=["HAWKI_FIXED_"+job["id"]]),max_rows=1)
            hid=identifier(data,HUNT)
            with self.db.connect(True) as conn:
                conn.execute("UPDATE jobs SET hunt_id=?,hunt_state='paused' WHERE id=?",(hid,job["id"]))
                self.db.event(conn,job["id"],"hunt_created","worker",dict(hunt_id=hid))
            return hid
        except Exception:
            with self.db.connect(True) as conn:
                conn.execute("UPDATE jobs SET hunt_state='unknown',error='hunt_submission_unknown' WHERE id=?",(job["id"],))
            raise

    def dispatch(self,u):
        job=self.db.get(u["job_id"]); m=job["manifest"]
        try:
            spec=validate_dispatch(self.t,m)
            if u["client_id"] not in m["client_ids"] or u["artifact"] not in spec:
                raise Invalid("Target mismatch")
            target=reader.client(self.t,u["client_id"])
            if str(target.get("os","")).lower()!="linux": raise Invalid("Unsupported OS")
        except (RemoteError,Invalid):
            self.db.unit(u["id"],state="failed",error="preflight_failed")
            return
        try:
            hid=self.hunt(job)
        except Exception:
            # This component has not been sent; stop the job because native hunt
            # creation may have succeeded. Never create another hunt blindly.
            self.db.unit(u["id"],state="failed",error="hunt_submission_unknown")
            return
        # Check cancellation again after read-only preflight/hunt creation.
        current=self.db.get(job["id"])
        if current["state"]=="cancel_requested":
            self.db.unit(u["id"],state="cancelled")
            return
        try:
            data=run(self.t,COLLECT,dict(client_id=u["client_id"],artifacts=[u["artifact"]],env=spec[u["artifact"]],limits=m["limits"]),max_rows=1)
            fid=identifier(data,FLOW)
            self.db.unit(u["id"],state="submitted",flow_id=fid)
        except Exception:
            self.db.unit(u["id"],state="submission_unknown",error="submission_unknown")
            return
        if hid:
            self.link(u["id"],hid,u["client_id"],fid)

    def link(self,uid,hid,cid,fid):
        try:
            response=run(self.t,LINK_HUNT,dict(hunt_id=hid,client_id=cid,flow_id=fid),max_rows=1)
            if not response or response[0].get("result") is None:
                raise RemoteError("hunt_link_failed")
            self.db.unit(uid,linked=1)
        except RemoteError:
            # The flow still exists and is shown even if adding it to the hunt fails.
            self.db.unit(uid,linked=-1,error="hunt_link_failed")

    def poll(self):
        with self.db.connect() as conn:
            units=[dict(x) for x in conn.execute("SELECT * FROM units WHERE state IN ('submitted','cancel_requested') ORDER BY updated LIMIT 6")]
        for u in units:
            self.db.beat(True)
            try:
                # Cancellation is sent once. A successful RPC is only a request;
                # subsequent native status determines the outcome.
                if u["state"]=="cancel_requested" and u["error"]!="cancel_sent":
                    response=run(self.t,CANCEL,dict(client_id=u["client_id"],flow_id=u["flow_id"]),max_rows=1)
                    if not response or response[0].get("result") is None:
                        raise RemoteError("cancel_not_confirmed")
                    self.db.unit(u["id"],error="cancel_sent")
                info=reader.flow(self.t,u["client_id"],u["flow_id"])
                native=str(info.get("state","")).upper()
                state={"FINISHED":"finished","ERROR":"failed","CANCELLED":"cancelled","CANCELED":"cancelled"}.get(native,u["state"])
                if state!=u["state"] or json.dumps(info,ensure_ascii=False)!=u["native"]:
                    self.db.unit(u["id"],state=state,native=info)
                if not u["linked"]:
                    job=self.db.get(u["job_id"])
                    if job["hunt_id"]:
                        self.link(u["id"],job["hunt_id"],u["client_id"],u["flow_id"])
            except (RemoteError,Invalid):
                # Keep the last recorded outcome; a failed status read is not a
                # successful empty result and must never trigger another collection.
                continue

    def tick(self):
        probe=run(self.t,"SELECT whoami() AS identity FROM scope()",max_rows=1)
        if not probe or not probe[0].get("identity"):
            raise RemoteError("connection_failed")
        self.db.beat(True)
        self.poll()
        self.db.finish_jobs()
        unit=self.db.claim()
        if unit:
            self.dispatch(unit)
        self.db.finish_jobs()


def main():
    db=Store()
    lock=db.path.with_suffix(".worker.lock").open("w")
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("An execution worker already owns this queue.")
    db.recover()
    config=os.getenv("VELOCIRAPTOR_EXEC_API_CONFIG","")
    worker=Worker(db,Transport(config_path=config))
    stopped=False
    def stop(*_):
        nonlocal stopped
        stopped=True
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    while not stopped:
        try:
            if not config or not Path(config).is_file():
                db.beat(False,"not_configured")
            else:
                worker.tick()
        except Exception as exc:
            db.beat(False,"connection_failed")
            print("Velociraptor worker:",type(exc).__name__,file=sys.stderr,flush=True)
        for _ in range(5):
            if stopped: break
            time.sleep(1)
    db.beat(False,"stopped")


if __name__=="__main__":
    main()
