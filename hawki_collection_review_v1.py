"""Owned, evidence-linked proposal cards and a handoff to native collection review."""
import json
import re
import time
from datetime import datetime, timezone
from flask import g, jsonify, request, current_app
from hawki_collection_contract_v1 import validate, evidence_for, proposal_id, digest, encoded
from hawki_vr.catalog import plan, Invalid
from hawki_vr.service import preview
from hawki_vr.transport import RemoteError


def tables(db):
    db.execute('''CREATE TABLE IF NOT EXISTS collection_proposals_v1 (
        user_id INTEGER NOT NULL, session_id TEXT NOT NULL, id TEXT NOT NULL,
        request_id TEXT NOT NULL, created_at TEXT NOT NULL, content TEXT NOT NULL,
        PRIMARY KEY(user_id,session_id,id),
        FOREIGN KEY(session_id,user_id) REFERENCES chat_sessions(id,user_id) ON DELETE CASCADE)''')
    db.commit()


def prepare_result(owner, session, request_id, result):
    """Runtime output is checked again before its proposals become reviewable."""
    items = result.get('proposals', [])
    if not items: return []
    if not isinstance(items,list) or len(items)>3:
        raise ValueError('Invalid proposal count.')
    accepted=[]
    for item in items:
        if not isinstance(item,dict) or set(item)!={'id','tool','arguments'} or item['tool']!='propose_collection':
            raise ValueError('Unsupported proposal tool.')
        p=validate(item['arguments'])
        records=evidence_for(p,result.get('tool_trace',[]))
        if item['id']!=proposal_id(owner,session,request_id,p):
            raise ValueError('Proposal ownership or request identity mismatch.')
        params,spec=plan(p['operation'],p['params'])
        accepted.append(dict(id=item['id'],tool='propose_collection',proposal=p,
            normalized_params=params,artifacts=list(spec),evidence=records))
    if len({p['id'] for p in accepted})!=len(accepted):
        raise ValueError('Duplicate proposal.')
    return accepted


def persist(db, owner, session, request_id, result):
    """Called inside investigation_finish's existing commit/rollback transaction."""
    for item in result.pop('_validated_collection_proposals', []):
        content=encoded(item).decode()
        db.execute('''INSERT OR IGNORE INTO collection_proposals_v1
            (user_id,session_id,id,request_id,created_at,content) VALUES(?,?,?,?,?,?)''',
            (owner,session,item['id'],request_id,datetime.now(timezone.utc).isoformat(),content))
        existing=db.execute('SELECT content FROM collection_proposals_v1 WHERE user_id=? AND session_id=? AND id=?',
                            (owner,session,item['id'])).fetchone()
        if existing['content']!=content:
            raise ValueError('A saved proposal cannot be changed.')


def reconcile_proposals(owner,session,request_id,result):
    try:
        prepared=prepare_result(owner,session,request_id,result)
        result['_validated_collection_proposals']=prepared
        result['proposals']=[{'id':p['id'],'status':'proposed','executed':False} for p in prepared]
    except (ValueError,TypeError,KeyError,Invalid):
        result['_validated_collection_proposals']=[]
        result['proposals']=[]
        result['proposal_errors']=['Collection proposal validation failed; no reviewable proposal was saved.']


def fetch(db,owner,session,identifier):
    row=db.execute('''SELECT p.* FROM collection_proposals_v1 p JOIN chat_sessions s
        ON p.session_id=s.id AND p.user_id=s.user_id
        WHERE p.user_id=? AND p.session_id=? AND p.id=? AND s.mode='conversation' ''',
        (owner,session,identifier)).fetchone()
    if row is None: raise LookupError('Proposal not found.')
    return row,json.loads(row['content'])


def actor():
    return f"{g.user['id']}:{g.user['username']}"


def native_job(store,identifier):
    with store.connect() as db:
        row=db.execute('SELECT id FROM jobs WHERE actor=? AND idem=?',
                       (actor(),'hawki-proposal-'+identifier)).fetchone()
    return store.get(row['id']) if row else None


def status_item(row,p,store):
    j=native_job(store,p['id'])
    state='proposed' if not j else j['state']
    if j and state in {'draft','pending_approval'} and j['expires']<time.time(): state='expired'
    # A job's recorded status is not proof that its investigative purpose was met.
    flows=[]
    if j:
        for unit in j.get('units',[]):
            if unit.get('flow_id'):
                flows.append({k:unit.get(k) for k in ('client_id','flow_id','artifact','state')})
    return dict(id=p['id'],created_at=row['created_at'],status=state,
        operation=p['proposal']['operation'],client_ids=p['proposal']['client_ids'],
        params=p['normalized_params'],artifacts=p['artifacts'],rationale=p['proposal']['rationale'],
        evidence_refs=p['proposal']['evidence_refs'],job_id=j['id'] if j else None,
        flows=flows,approval_required=j['manifest']['approval_required'] if j else None)


def response_context(db,owner,session,budget=2000):
    store=current_app.extensions['hawki_vr']['store']
    rows=db.execute('''SELECT * FROM collection_proposals_v1
        WHERE user_id=? AND session_id=? ORDER BY created_at DESC LIMIT 6''',(owner,session)).fetchall()
    items=[]
    for row in rows:
        full=status_item(row,json.loads(row['content']),store)
        item={k:full[k] for k in ('id','status','operation','client_ids','job_id','evidence_refs','approval_required')}
        item.update(flows=full['flows'][:20],flows_truncated=len(full['flows'])>20)
        items.append(item)
    result={'checked_at':datetime.now(timezone.utc).isoformat(),
        'coverage':'Up to six recent owned collection proposals and recorded native job states. '
                   'Flow completion does not establish investigation success.',
        'items':items,'context_truncated':False}
    while len(encoded(result))>budget and result['items']:
        result['context_truncated']=True
        last=result['items'][-1]
        if last['flows']:
            last['flows'].pop();last['flows_truncated']=True
        else:
            result['items'].pop()
    return result


class BoundedReads:
    def __init__(self,transport):
        self.transport=transport; self.deadline=time.monotonic()+24
    def query(self,*args,**kwargs):
        remaining=self.deadline-time.monotonic()
        if remaining<3: raise RemoteError('timeout')
        kwargs['timeout']=min(kwargs.get('timeout',20),max(1,int(remaining)-1))
        return self.transport.query(*args,**kwargs)


def install(app,db_get,role_required,audit):
    with app.app_context(): tables(db_get())

    @app.after_request
    def collection_proposal_no_cache(response):
        if '/collection-proposals' in request.path:
            response.headers['Cache-Control']='no-store'
        return response

    def owned(session):
        if db_get().execute("SELECT 1 FROM chat_sessions WHERE id=? AND user_id=? AND mode='conversation'",
                            (session,g.user['id'])).fetchone() is None:
            raise LookupError('Conversation not found.')

    @app.get('/api/agent/workspace/sessions/<session_id>/collection-proposals')
    @role_required('analyst')
    def collection_proposals(session_id):
        try:
            owned(session_id)
            if set(request.args)-{'offset'} or any(len(request.args.getlist(k))!=1 for k in request.args):
                return jsonify(error='Invalid pagination.'),400
            raw=request.args.get('offset','0')
            if not re.fullmatch(r'[0-9]{1,5}',raw) or int(raw)>10000:
                return jsonify(error='Invalid pagination.'),400
            offset=int(raw)
            rows=db_get().execute('''SELECT * FROM collection_proposals_v1 WHERE user_id=? AND session_id=?
                ORDER BY created_at DESC,id DESC LIMIT 31 OFFSET ?''',(g.user['id'],session_id,offset)).fetchall()
            store=app.extensions['hawki_vr']['store']
            items=[status_item(r,json.loads(r['content']),store) for r in rows[:30]]
            return jsonify(items=items,has_more=len(rows)>30,next_offset=offset+30 if len(rows)>30 else None)
        except LookupError:
            return jsonify(error='Conversation not found.'),404

    @app.get('/api/agent/workspace/sessions/<session_id>/collection-proposals/<proposal_id>')
    @role_required('analyst')
    def collection_proposal(session_id,proposal_id):
        try:
            row,p=fetch(db_get(),g.user['id'],session_id,proposal_id)
            return jsonify(**status_item(row,p,app.extensions['hawki_vr']['store']),evidence=p['evidence'])
        except LookupError:
            return jsonify(error='Proposal not found.'),404

    @app.post('/api/agent/workspace/sessions/<session_id>/collection-proposals/<proposal_id>/review')
    @role_required('analyst')
    def collection_proposal_review(session_id,proposal_id):
        if request.get_json(silent=True)!={}:
            return jsonify(error='Review accepts the saved proposal only; parameters cannot be overridden.'),400
        try:
            row,p=fetch(db_get(),g.user['id'],session_id,proposal_id)
            ext=app.extensions['hawki_vr']; store=ext['store']
            job=native_job(store,proposal_id)
            if job and job['state'] in {'draft','pending_approval'} and job['expires']<time.time():
                return jsonify(error='This review expired. Request a fresh proposal with current evidence.'),409
            if job is None:
                op=p['proposal']['operation']
                normalized,spec=plan(op,p['proposal']['params'])
                if normalized!=p['normalized_params'] or list(spec)!=p['artifacts']:
                    return jsonify(error='Collection definitions changed. Request a fresh proposal.'),409
                job=preview(BoundedReads(ext['transport']),store,actor(),{
                    'operation':op,'client_ids':p['proposal']['client_ids'],'params':normalized,
                    'incident':proposal_id,'hunt':len(p['proposal']['client_ids'])>1,
                    'idempotency_key':'hawki-proposal-'+proposal_id})
                audit('agent_collection_review_created',{'session_id':session_id,
                    'proposal_id':proposal_id,'job_id':job['id'],'evidence_refs':p['proposal']['evidence_refs']})
            return jsonify(job_id=job['id'],state=job['state'],
                review_url='/response?hawki_review='+job['id'],created_collection=False)
        except LookupError:
            return jsonify(error='Proposal not found.'),404
        except Invalid as exc:
            return jsonify(error=str(exc)),400
        except RemoteError:
            return jsonify(error='Collection targets or definitions could not be verified. Retry the review.'),503
