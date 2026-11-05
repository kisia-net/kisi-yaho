"""Session-owned evidence archive, independent of the model's bounded memory."""
import json
import re
from flask import g, jsonify, request

REF = re.compile(r'E-[a-f0-9]{32}')

def tables(db):
    db.execute('''CREATE TABLE IF NOT EXISTS workspace_evidence_v1 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL, session_id TEXT NOT NULL, ref TEXT NOT NULL,
        content TEXT NOT NULL,
        UNIQUE(user_id,session_id,ref),
        FOREIGN KEY(session_id,user_id) REFERENCES chat_sessions(id,user_id) ON DELETE CASCADE)''')

def persist(db, owner, session, records):
    """Caller owns the transaction. Keep original evidence, including its result hash."""
    for record in records:
        if not isinstance(record, dict) or not REF.fullmatch(str(record.get('ref', ''))):
            continue
        content = json.dumps(record, ensure_ascii=False, allow_nan=False)
        old = db.execute('SELECT content FROM workspace_evidence_v1 WHERE user_id=? AND session_id=? AND ref=?',
                         (owner, session, record['ref'])).fetchone()
        if old:
            prior = json.loads(old['content'])
            # recorded_at can be added by conversation persistence after the tool call.
            if {k:v for k,v in prior.items() if k!='recorded_at'} != {k:v for k,v in record.items() if k!='recorded_at'}:
                raise ValueError('Evidence reference conflicts with its archived record.')
            continue
        db.execute('INSERT INTO workspace_evidence_v1(user_id,session_id,ref,content) VALUES(?,?,?,?)',
                   (owner, session, record['ref'], content))

def seed(db, owner, session):
    """Recover retained full records only; never reconstruct evidence from model text."""
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chat_investigations'").fetchone()
    row = db.execute('SELECT state_json,result_json FROM chat_investigations WHERE user_id=? AND session_id=?',
                     (owner,session)).fetchone() if exists else None
    if row:
        state=json.loads(row['state_json'] or '{}') or {}
        result=json.loads(row['result_json'] or '{}') or {}
        persist(db,owner,session,state.get('evidence',[]))
        persist(db,owner,session,result.get('tool_trace',[]))
    row=db.execute('SELECT last_result_json FROM chat_sessions WHERE user_id=? AND id=?',(owner,session)).fetchone()
    if row:
        persist(db,owner,session,(json.loads(row['last_result_json'] or '{}') or {}).get('tool_trace',[]))
    for row in db.execute('SELECT content FROM collection_proposals_v1 WHERE user_id=? AND session_id=?',(owner,session)):
        persist(db,owner,session,json.loads(row['content']).get('evidence',[]))

def install(app, db_get, role_required):
    with app.app_context():
        tables(db_get())
        db_get().commit()

    @app.after_request
    def evidence_no_cache(response):
        if request.path.startswith('/api/agent/workspace/sessions/') and '/evidence' in request.path:
            response.headers['Cache-Control']='no-store'
        return response

    def owned(session):
        db=db_get()
        row=db.execute('SELECT 1 FROM chat_sessions WHERE user_id=? AND id=?',(g.user['id'],session)).fetchone()
        if row is None:
            return None
        try:
            seed(db,g.user['id'],session)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return db

    @app.get('/api/agent/workspace/sessions/<session_id>/evidence')
    @role_required('analyst')
    def workspace_evidence_list(session_id):
        if set(request.args)-{'before'} or any(len(request.args.getlist(k))!=1 for k in request.args):
            return jsonify(error='Invalid pagination.'),400
        raw=request.args.get('before','')
        if raw and (not re.fullmatch(r'[0-9]{1,18}',raw) or int(raw)<1):
            return jsonify(error='Invalid pagination.'),400
        db=owned(session_id)
        if db is None:return jsonify(error='Conversation not found.'),404
        where='user_id=? AND session_id=?';args=[g.user['id'],session_id]
        total=db.execute('SELECT COUNT(*) FROM workspace_evidence_v1 WHERE '+where,args).fetchone()[0]
        if raw:where+=' AND sequence<?';args.append(int(raw))
        rows=db.execute('SELECT sequence,content FROM workspace_evidence_v1 WHERE '+where+' ORDER BY sequence DESC LIMIT 21',args).fetchall()
        items=[]
        for row in rows[:20]:
            record=json.loads(row['content']);result=record.get('result') or {}
            items.append({'ref':record['ref'],'tool':record.get('tool',''),
                          'status':result.get('status','unknown'),'recorded_at':record.get('recorded_at')})
        return jsonify(items=items,total=total,has_more=len(rows)>20,
                       next_before=rows[19]['sequence'] if len(rows)>20 else None,
                       coverage='Saved evidence only; older records removed before archiving may be unavailable.')

    @app.get('/api/agent/workspace/sessions/<session_id>/evidence/<ref>')
    @role_required('analyst')
    def workspace_evidence_detail(session_id,ref):
        if not REF.fullmatch(ref) or request.args:return jsonify(error='Invalid evidence reference.'),400
        db=owned(session_id)
        if db is None:return jsonify(error='Conversation not found.'),404
        row=db.execute('SELECT content FROM workspace_evidence_v1 WHERE user_id=? AND session_id=? AND ref=?',
                       (g.user['id'],session_id,ref)).fetchone()
        if row is None:return jsonify(error='This evidence record is not retained in this conversation.'),404
        return jsonify(record=json.loads(row['content']))
