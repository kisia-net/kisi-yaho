"""Shared collection proposal validation. No network, submission, or execution."""
import hashlib
import json
import re

OPERATIONS = {'files','hash','yara','directory','acquire','processes','network',
              'services','cron','keys','users','logins','disk','triage'}

def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

def validate(arguments):
    keys = {'operation','client_ids','params','rationale','evidence_refs'}
    if not isinstance(arguments,dict) or set(arguments)!=keys or len(encoded(arguments))>10000:
        raise ValueError('Invalid collection proposal fields.')
    op, ids, params, rationale, refs = (arguments[k] for k in
        ('operation','client_ids','params','rationale','evidence_refs'))
    if not isinstance(op,str) or op not in OPERATIONS:
        raise ValueError('Unsupported collection operation.')
    if (not isinstance(ids,list) or not 1<=len(ids)<=10 or
        any(not isinstance(c,str) or not re.fullmatch(r'C\.[a-fA-F0-9]{16,64}',c) for c in ids)
        or len(set(ids))!=len(ids)):
        raise ValueError('Use distinct exact client identifiers.')
    if (not isinstance(params,dict) or set(params)-
        {'path','after','before','hash','sha256','max_size','rule','days'}):
        raise ValueError('Unsupported collection parameters.')
    for key,value in params.items():
        if key in {'days','max_size'}:
            if type(value) is not int or not 1<=value<=(30 if key=='days' else 100):
                raise ValueError('Invalid collection limit.')
        elif key=='hash':
            if type(value) is not bool: raise ValueError('Invalid hash option.')
        elif (not isinstance(value,str) or len(value)>(6000 if key=='rule' else 500)
              or (not value.strip() and key not in {'after','before'})
              or any(ord(c)<32 and c not in '\n\t' for c in value)):
            raise ValueError('Invalid collection parameter.')
    if (not isinstance(rationale,str) or not rationale.strip() or len(rationale)>1200
        or any(ord(c)<32 and c not in '\n\t' for c in rationale)):
        raise ValueError('Explain the investigative purpose and expected evidence.')
    if (not isinstance(refs,list) or not 1<=len(refs)<=8 or
        any(not isinstance(r,str) or not re.fullmatch(r'E-[a-f0-9]{32}',r) for r in refs)
        or len(set(refs))!=len(refs)):
        raise ValueError('Cite returned evidence, including capabilities and exact targets.')
    return dict(arguments,kind='velociraptor',client_ids=sorted(ids),rationale=rationale.strip())

def evidence_for(proposal, trace):
    if not isinstance(trace,list): raise ValueError('Evidence records are required.')
    records={}
    for r in trace:
        if not isinstance(r,dict) or r.get('ref') not in proposal['evidence_refs']: continue
        if r['ref'] in records: raise ValueError('Duplicate evidence reference.')
        result=r.get('result')
        if (not isinstance(result,dict) or result.get('status') not in {'success','partial'}
            or digest(result)!=r.get('result_sha256')):
            raise ValueError('Proposal evidence is unsuccessful or has an invalid digest.')
        records[r['ref']]=r
    if set(records)!=set(proposal['evidence_refs']):
        raise ValueError('Use evidence returned during this turn; retrieve it again if needed.')
    supported=False; clients=set()
    for r in records.values():
        result=r['result']
        if r.get('tool')=='response_capabilities':
            supported= supported or any(o.get('id')==proposal['operation'] and
                o.get('definitions_available') is True for o in result.get('operations',[]) if isinstance(o,dict))
        elif r.get('tool')=='list_velociraptor_clients':
            clients.update(c.get('client_id') for c in result.get('items',[]) if isinstance(c,dict))
        elif r.get('tool') in {'get_collection_flow','read_collection_results'}:
            cid=result.get('client_id')
            if cid and cid==r.get('arguments',{}).get('client_id'):
                clients.add(cid)
    if not supported:
        raise ValueError('Read and cite available collection capabilities for this operation.')
    if not set(proposal['client_ids'])<=clients:
        raise ValueError('Resolve and cite every exact target from client inventory or an existing flow.')
    ordered=[records[ref] for ref in proposal['evidence_refs']]
    if len(encoded(ordered))>100000:
        raise ValueError('Supporting evidence is too large; retrieve a narrower result.')
    return ordered

def proposal_id(owner,session,request,proposal):
    return 'WP-'+digest([str(owner),session,request,proposal])[:24]

def validate_runtime(proposal,trace):
    # Validate against the same normalized representation used in the frontend.
    if proposal.get('kind')!='velociraptor':
        raise ValueError('Only collection proposals are enabled.')
    normalized=validate({k:v for k,v in proposal.items() if k!='kind'})
    evidence_for(normalized,trace)
    return normalized
