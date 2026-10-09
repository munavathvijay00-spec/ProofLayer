#!/usr/bin/env python3
"""Measure actual model proposals. Credentials are read from environment only."""
import argparse,json,os,sys,time,urllib.request,urllib.error
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--api',default='http://localhost:8000')
parser.add_argument('--mode',choices=['live','replay'],default='live')
parser.add_argument('--trials',type=int,choices=range(1,4),default=1)
parser.add_argument('--scenario',action='append',choices=['safe','email_exfiltration','file_exfiltration','unauthorized_invoice'])
parser.add_argument('--output',default='evidence/live-evaluation.json')
args=parser.parse_args()
body={'agent_mode':args.mode,'trials':args.trials}
if args.scenario:body['scenarios']=args.scenario
headers={'Content-Type':'application/json'}
if os.getenv('CONSOLE_API_KEY'):headers['X-Console-Key']=os.environ['CONSOLE_API_KEY']
request=urllib.request.Request(args.api.rstrip('/')+'/evaluations',data=json.dumps(body).encode(),headers=headers,method='POST')
try:
    with urllib.request.urlopen(request,timeout=1800) as response:result=json.load(response)
except urllib.error.HTTPError as exc:
    try:detail=json.load(exc).get('detail','Request failed')
    except Exception:detail='Request failed'
    print(f'HTTP {exc.code}: {detail}',file=sys.stderr);sys.exit(1)
except urllib.error.URLError:
    print('Backend unavailable. Start the API and verify its URL.',file=sys.stderr);sys.exit(1)
if result.get('job_id'):
    job_id=result['job_id']
    while True:
        time.sleep(1)
        poll=urllib.request.Request(args.api.rstrip('/')+'/evaluations/'+job_id,headers=headers)
        with urllib.request.urlopen(poll,timeout=30) as response:job=json.load(response)
        if job['status']=='completed':result=job['result'];break
        if job['status'] in ('failed','interrupted'):
            print('Evaluation failed or was interrupted.',file=sys.stderr);sys.exit(2)
output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2))
print(json.dumps({'agent_mode':result['agent_mode'],'metrics':result['metrics'],'comparison':result['comparison'],'evidence':str(output)},indent=2))
if result['metrics']['failed_runs'] or result['metrics']['protected_unauthorized_effects']:sys.exit(2)
