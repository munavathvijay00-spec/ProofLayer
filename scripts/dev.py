#!/usr/bin/env python3
"""Launch both local services. Install dependencies first; stop both with Ctrl+C."""
import os,subprocess,sys,time,signal,argparse,shutil
from pathlib import Path
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--production',action='store_true',help='Use the built standalone Next.js server')
args=parser.parse_args()
children=[]
try:
    children.append(subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8000'],cwd=root/'backend'))
    env={**os.environ,'HOSTNAME':'127.0.0.1','PORT':'3000'}
    if args.production:
        server=root/'frontend/.next/standalone/server.js'
        if not server.exists():raise RuntimeError('Build the frontend first: cd frontend && npm run build')
        shutil.copytree(root/'frontend/.next/static',root/'frontend/.next/standalone/.next/static',dirs_exist_ok=True)
        command=['node',str(server)]
    else:command=['npm','run','dev','--','--hostname','127.0.0.1']
    children.append(subprocess.Popen(command,cwd=root/'frontend',env=env))
    print('ProofLayer console: http://localhost:3000\nAPI: http://localhost:8000',flush=True)
    while all(child.poll() is None for child in children):time.sleep(.2)
    if any(child.returncode for child in children if child.poll() is not None):sys.exit(1)
except KeyboardInterrupt:pass
except RuntimeError as exc:print(str(exc),file=sys.stderr);sys.exit(1)
finally:
    for child in children:
        if child.poll() is None:child.terminate()
    for child in children:
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:child.kill();child.wait()
