import os, secrets
from fastapi import FastAPI, HTTPException, Header, Depends, Query, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from .schemas import Action, RunRequest, TaskRequest, Proposal, EvaluationRequest
from .policy import POLICY, evaluate
from .store import Store
from .gateway import Gateway
from .agent import run_agent
from .scenarios import SCENARIOS
from .evaluation import evaluate_suite as run_suite, run_live_job

store = Store(os.getenv('DB_PATH','data/prooflayer.db'))
gateway = Gateway(store)
app = FastAPI(title='ProofLayer Execution Firewall', version='0.3.0')
app.add_middleware(CORSMiddleware,allow_origins=os.getenv('CORS_ORIGINS','http://localhost:3000').split(','),allow_methods=['GET','POST'],allow_headers=['Content-Type','X-Console-Key','Authorization'])

def console_auth(x_console_key: str = Header(default='')):
    expected = os.getenv('CONSOLE_API_KEY','')
    if expected and not secrets.compare_digest(x_console_key,expected):
        raise HTTPException(401,'Console credential required')
    if os.getenv('ENVIRONMENT') == 'production' and not expected:
        raise HTTPException(503,'Production requires CONSOLE_API_KEY')

@app.get('/health')
def health():
    return {'status':'ok','version':'0.3.0','live_available':bool(os.getenv('OPENAI_API_KEY')),'executor':'local-synthetic-lab'}
@app.get('/policy',dependencies=[Depends(console_auth)])
def policy(): return POLICY
@app.get('/scenarios',dependencies=[Depends(console_auth)])
def scenarios(): return [{'id':key,**value} for key,value in SCENARIOS.items()]
@app.post('/tasks',dependencies=[Depends(console_auth)])
def create_task(req:TaskRequest):
    task = store.create_task(req.scenario)
    task['run_id'] = store.start_run(task['task_id'],True,'external')
    return task
@app.post('/tasks/{task_id}/proposals')
def proposal(task_id:str, req:Proposal, run_id:str=Query(...), authorization:str=Header(default='')):
    if not authorization.startswith('Bearer '): raise HTTPException(401,'Task bearer credential required')
    try:
        return gateway.propose(task_id,authorization[7:],run_id,req.action,req.call_id)
    except PermissionError as exc: raise HTTPException(403,str(exc))
    except ValueError as exc: raise HTTPException(409,str(exc))
@app.post('/runs',dependencies=[Depends(console_auth)])
def run(req:RunRequest):
    if req.agent_mode == 'live' and not os.getenv('OPENAI_API_KEY'):
        raise HTTPException(503,'Live mode requires backend OPENAI_API_KEY; replay mode remains available')
    return run_agent(store,gateway,req.scenario,req.protected,req.agent_mode)
@app.get('/runs/{run_id}',dependencies=[Depends(console_auth)])
def get_run(run_id:str):
    with store.connect() as c:
        row = c.execute('SELECT runs.*,tasks.scenario,tasks.policy FROM runs JOIN tasks ON tasks.id=runs.task_id WHERE runs.id=?',(run_id,)).fetchone()
    if not row: raise HTTPException(404,'Run not found')
    import json
    if not row['result']:
        event_list=store.events(run_id=run_id);effect_list=store.effects(run_id)
        unauthorized={e['id'] for e in event_list if not evaluate(Action(tool=e['tool'],args=e['args']),json.loads(row['policy'])).allowed}
        result={'run_id':run_id,'task_id':row['task_id'],'scenario':row['scenario'],'mode':row['mode'],'agent_mode':row['agent_mode'],'status':row['status'],'events':event_list,'effects':effect_list,'transcript':[],'attack_attempted':bool(unauthorized),'attack_blocked':bool(unauthorized) and all(e['decision']=='DENY' for e in event_list if e['id'] in unauthorized),'unauthorized_effects':sum(e['event_id'] in unauthorized for e in effect_list),'error':None,'final_message':None}
    else:result=json.loads(row['result'])
    result['task_completed']=any(e['kind']=='summary' and e['payload'].get('facts_verified') is True for e in result.get('effects',[]))
    return result
@app.get('/events',dependencies=[Depends(console_auth)])
def events(limit:int=Query(100,ge=1,le=200)): return store.events(limit)
@app.get('/metrics',dependencies=[Depends(console_auth)])
def metrics(): return store.metrics()
@app.post('/evaluations',dependencies=[Depends(console_auth)])
def evaluate_suite(background_tasks:BackgroundTasks,response:Response,req:EvaluationRequest = EvaluationRequest()):
    if req.agent_mode=='live' and not os.getenv('OPENAI_API_KEY'):
        raise HTTPException(503,'Live evaluations require backend OPENAI_API_KEY')
    if req.agent_mode=='live':
        try:job_id=store.create_job(len(req.scenarios)*req.trials*2)
        except ValueError as exc:raise HTTPException(409,str(exc))
        background_tasks.add_task(run_live_job,store,gateway,req,job_id)
        response.status_code=202
        return {'job_id':job_id,'status':'queued','total_runs':len(req.scenarios)*req.trials*2}
    return run_suite(store,gateway,req)

@app.get('/evaluations/{job_id}',dependencies=[Depends(console_auth)])
def evaluation_job(job_id:str):
    job=store.job(job_id)
    if not job:raise HTTPException(404,'Evaluation job not found')
    return job
