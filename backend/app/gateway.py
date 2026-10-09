import json, time
from uuid import uuid4
from .schemas import Action, TOOLS
from .policy import evaluate, Decision
from .scenarios import SCENARIOS, INVOICE
from .store import now

class Gateway:
    """Only this object owns executor dispatch. The model gets tool results, never credentials or a dispatcher."""
    def __init__(self, store):
        self.store = store

    def propose(self, task_id, token, run_id, action: Action, call_id, *, protected=True):
        start = time.perf_counter()
        task = self.store.authenticate(task_id, token)
        decision = evaluate(action, task['policy'])
        # Baseline bypasses authorization only. Unknown tools and malformed input still cannot dispatch.
        if not protected and decision.code not in ('UNKNOWN_TOOL','INVALID_ARGUMENTS'):
            decision = Decision(True, 'LAB_BYPASS', 'Authorization bypassed inside the synthetic local lab')
        event_id = str(uuid4())
        with self.store.connect() as c:
            # Serialize same-call retries with dispatch to avoid duplicate side effects.
            c.execute('BEGIN IMMEDIATE')
            run = c.execute('SELECT * FROM runs WHERE id=? AND task_id=?',(run_id,task_id)).fetchone()
            if not run or run['mode'] != ('protected' if protected else 'baseline'):
                raise PermissionError('Run does not belong to this task or mode')
            existing = c.execute('SELECT * FROM decisions WHERE task_id=? AND call_id=?',(task_id,call_id)).fetchone()
            if existing:
                if existing['run_id'] != run_id or existing['tool'] != action.tool or json.loads(existing['args']) != action.args:
                    raise ValueError('Call ID already used with another proposal')
                return {'event_id':existing['id'],'decision':existing['decision'],'code':existing['code'],'reason':existing['reason'],'result':json.loads(existing['result']) if existing['result'] else None,'replayed':True}
            if run['status'] != 'running':
                raise PermissionError('Run is closed')
            if decision.allowed and action.tool == 'write_summary':
                args = TOOLS[action.tool].model_validate(action.args)
                read = c.execute("SELECT 1 FROM decisions WHERE run_id=? AND tool='read_invoice' AND executed=1 AND json_extract(args,'$.invoice_id')=?", (run_id,args.invoice_id)).fetchone()
                if not read:
                    decision = Decision(False,'SOURCE_NOT_READ','Read the source invoice through the gateway before saving a summary')
                elif args.facts.model_dump() != task['document']['facts'] or args.invoice_id != args.facts.invoice_id:
                    decision = Decision(False,'SUMMARY_MISMATCH','Submitted invoice facts do not match the source document')
            # Audit decision is inserted before dispatch; decision and local effects commit atomically.
            c.execute('INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (event_id,task_id,run_id,call_id,now(),run['mode'],action.tool,json.dumps(action.args),
                 'ALLOW' if decision.allowed else 'DENY',decision.code,decision.reason,0,None,0))
            result = None
            if decision.allowed:
                result = self._dispatch(c, event_id, run_id, action, task['scenario'])
            c.execute('UPDATE decisions SET executed=?,result=?,latency_ms=? WHERE id=?',
                (int(decision.allowed),json.dumps(result) if result is not None else None,(time.perf_counter()-start)*1000,event_id))
        return {'event_id':event_id,'decision':'ALLOW' if decision.allowed else 'DENY','code':decision.code,'reason':decision.reason,'result':result,'replayed':False}

    @staticmethod
    def _dispatch(c, event_id, run_id, action, scenario):
        args = TOOLS[action.tool].model_validate(action.args)
        row=c.execute('SELECT tasks.document FROM tasks JOIN runs ON tasks.id=runs.task_id WHERE runs.id=?',(run_id,)).fetchone()
        from .scenarios import document_for
        document=json.loads(row['document']) if row['document'] else document_for(scenario)
        if action.tool == 'read_invoice':
            if args.invoice_id == document['facts']['invoice_id']:
                return {**document['facts'],'untrusted_document':document['content'],'source_kind':document['source_kind']}
            payload = {'invoice_id':args.invoice_id,'vendor':'Synthetic restricted customer','amount':9000,'currency':'USD'}
            c.execute('INSERT INTO effects VALUES(?,?,?,?,?,?)',(str(uuid4()),run_id,event_id,'restricted_read',args.invoice_id,json.dumps(payload)))
            return payload
        if action.tool == 'write_summary':
            payload = {**args.facts.model_dump(),'source_invoice_id':args.invoice_id,'agent_summary':args.summary,'facts_verified':True}
            kind, target = 'summary', args.path
        elif action.tool == 'send_email':
            payload, kind, target = {'body':args.body}, 'outbox', args.to
        else:
            payload, kind, target = {'source':args.path,'content':document['content'],'source_kind':document['source_kind']}, 'export_receipt', args.destination
        c.execute('INSERT INTO effects VALUES(?,?,?,?,?,?)',(str(uuid4()),run_id,event_id,kind,target,json.dumps(payload)))
        return {'status':'persisted_in_local_lab','kind':kind,'target':target,'payload':payload}
