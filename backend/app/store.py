import sqlite3, json, hashlib, secrets, copy
from .scenarios import document_for
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from pathlib import Path
from .policy import POLICY

def now():
    return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, scenario TEXT NOT NULL, policy TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, task_id TEXT NOT NULL, created_at TEXT NOT NULL, mode TEXT NOT NULL, agent_mode TEXT NOT NULL, status TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, task_id TEXT NOT NULL, run_id TEXT NOT NULL, call_id TEXT NOT NULL, created_at TEXT NOT NULL, mode TEXT NOT NULL, tool TEXT NOT NULL, args TEXT NOT NULL, decision TEXT NOT NULL, code TEXT NOT NULL, reason TEXT NOT NULL, executed INTEGER NOT NULL DEFAULT 0, result TEXT, latency_ms REAL NOT NULL, UNIQUE(task_id,call_id));
            CREATE TABLE IF NOT EXISTS evaluation_jobs(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL, result TEXT, completed_runs INTEGER NOT NULL DEFAULT 0, total_runs INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS effects(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, target TEXT NOT NULL, payload TEXT NOT NULL);
            ''')
            c.execute('CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, filename TEXT NOT NULL, facts TEXT NOT NULL, content TEXT NOT NULL)')
            if 'document' not in [r['name'] for r in c.execute('PRAGMA table_info(tasks)')]:
                c.execute('ALTER TABLE tasks ADD COLUMN document TEXT')
            c.execute("UPDATE evaluation_jobs SET status='interrupted' WHERE status IN ('queued','running')")
    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        try:
            with c:
                yield c
        finally:
            c.close()
    def create_task(self, scenario, document_id=None):
        task_id, token = str(uuid4()), secrets.token_urlsafe(32)
        expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        document = document_for(scenario,self.document(document_id) if document_id else None)
        policy = copy.deepcopy(POLICY)
        if document_id:policy['send_email']['recipients']=[]
        invoice_id = document['facts']['invoice_id']
        policy['read_invoice']['invoice_ids'] = [invoice_id]
        policy['write_summary']['invoice_ids'] = [invoice_id]
        policy['export_file']['paths'] = [f'/workspace/invoices/{invoice_id}.pdf']
        with self.connect() as c:
            c.execute('INSERT INTO tasks(id,token_hash,expires_at,scenario,policy,document) VALUES(?,?,?,?,?,?)', (task_id, hashlib.sha256(token.encode()).hexdigest(), expiry, scenario, json.dumps(policy),json.dumps(document)))
        return {'task_id': task_id, 'token': token, 'expires_at': expiry, 'policy': policy,'document':document}
    def import_document(self, request):
        document_id = str(uuid4())
        with self.connect() as c:
            c.execute('INSERT INTO documents VALUES(?,?,?,?,?)',(document_id,now(),request.filename,json.dumps(request.facts.model_dump()),request.content))
        return self.document(document_id)
    def document(self, document_id):
        with self.connect() as c:
            row=c.execute('SELECT * FROM documents WHERE id=?',(document_id,)).fetchone()
        if row is None:raise ValueError('Imported invoice not found')
        return {'document_id':row['id'],'created_at':row['created_at'],'filename':row['filename'],
                'facts':json.loads(row['facts']),'content':row['content']}
    def documents(self):
        with self.connect() as c:
            rows=c.execute('SELECT id,created_at,filename,facts FROM documents ORDER BY rowid DESC LIMIT 100').fetchall()
        return [{'document_id':r['id'],'created_at':r['created_at'],'filename':r['filename'],'facts':json.loads(r['facts'])} for r in rows]
    def authenticate(self, task_id, token):
        with self.connect() as c:
            row = c.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not row or not secrets.compare_digest(row['token_hash'], hashlib.sha256(token.encode()).hexdigest()) or row['expires_at'] <= now():
            raise PermissionError('Invalid or expired task credential')
        return {**dict(row), 'policy': json.loads(row['policy']), 'document':json.loads(row['document']) if row['document'] else document_for(row['scenario'])}
    def start_run(self, task_id, protected, agent_mode):
        run_id = str(uuid4())
        with self.connect() as c:
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?)', (run_id,task_id,now(),'protected' if protected else 'baseline',agent_mode,'running',None))
        return run_id
    def finish_run(self, run_id, result):
        with self.connect() as c:
            c.execute('UPDATE runs SET status=?,result=? WHERE id=?', (result['status'],json.dumps(result),run_id))
    def events(self, limit=200, run_id=None, document_id=None):
        with self.connect() as c:
            if run_id:
                rows = c.execute('SELECT * FROM decisions WHERE run_id=? ORDER BY rowid',(run_id,)).fetchall()
            elif document_id:
                rows = c.execute("SELECT decisions.* FROM decisions JOIN tasks ON tasks.id=decisions.task_id WHERE json_extract(tasks.document,'$.document_id')=? ORDER BY decisions.rowid DESC LIMIT ?",(document_id,limit)).fetchall()
            else:
                rows = c.execute('SELECT * FROM decisions ORDER BY rowid DESC LIMIT ?',(limit,)).fetchall()
        return [{**dict(r),'args':json.loads(r['args']),'result':json.loads(r['result']) if r['result'] else None,'executed':bool(r['executed'])} for r in rows]
    def effects(self, run_id):
        with self.connect() as c:
            rows = c.execute('SELECT * FROM effects WHERE run_id=? ORDER BY rowid',(run_id,)).fetchall()
        return [{**dict(r),'payload':json.loads(r['payload'])} for r in rows]
    def metrics(self, document_id=None):
        with self.connect() as c:
            where=" WHERE json_extract(tasks.document,'$.document_id')=?" if document_id else ''
            params=(document_id,) if document_id else ()
            r = c.execute("SELECT COUNT(*) total, COALESCE(SUM(decision='DENY'),0) denied, COALESCE(SUM(executed),0) executed FROM decisions JOIN tasks ON tasks.id=decisions.task_id"+where,params).fetchone()
            runs = c.execute("SELECT COUNT(*) runs, COALESCE(SUM(status='completed' AND EXISTS(SELECT 1 FROM effects e WHERE e.run_id=runs.id AND e.kind='summary' AND json_extract(e.payload,'$.facts_verified')=1)),0) completed FROM runs JOIN tasks ON tasks.id=runs.task_id"+where,params).fetchone()
        return {**dict(r), **dict(runs)}

    def create_job(self,total_runs):
        job_id = str(uuid4())
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute("SELECT 1 FROM evaluation_jobs WHERE status IN ('queued','running')").fetchone():
                raise ValueError('A live evaluation is already running')
            c.execute('INSERT INTO evaluation_jobs VALUES(?,?,?,?,?,?)',(job_id,now(),'queued',None,0,total_runs))
        return job_id
    def update_job(self,job_id,status,result=None,completed_runs=0):
        with self.connect() as c:
            c.execute('UPDATE evaluation_jobs SET status=?,result=?,completed_runs=? WHERE id=?',(status,json.dumps(result) if result is not None else None,completed_runs,job_id))
    def job(self,job_id):
        with self.connect() as c:
            row=c.execute('SELECT * FROM evaluation_jobs WHERE id=?',(job_id,)).fetchone()
        if row is None:return None
        return {**dict(row),'result':json.loads(row['result']) if row['result'] else None}
