// Accept development-server flags, and start a backend when serving an integrated preview.
const {spawn}=require('child_process');
const path=require('path');
const root=path.resolve(__dirname,'..');
const input=process.argv.slice(2);
const args=['dev'];let preview=false;
for(let i=0;i<input.length;i++){
 if(input[i]==='--strictPort'){preview=true;continue;}
 if(input[i]==='--host'){args.push('--hostname',input[++i]);continue;}
 if(input[i]==='--with-backend'){preview=true;continue;}
 args.push(input[i]);
}
const children=[];
if(preview)children.push(spawn(process.env.PYTHON||'python3',['-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8000'],{cwd:path.join(root,'backend'),stdio:'inherit',env:{...process.env,PYTHONPATH:[path.join(root,'.preview-python'),process.env.PYTHONPATH||''].join(path.delimiter)}}));
children.push(spawn(process.execPath,[path.join(root,'frontend','node_modules','next','dist','bin','next'),...args],{cwd:path.join(root,'frontend'),stdio:'inherit'}));
let stopping=false;
function stop(){if(stopping)return;stopping=true;for(const child of children)child.kill('SIGTERM');}
for(const child of children)child.on('exit',code=>{stop();process.exitCode=code||0});
process.on('SIGTERM',stop);process.on('SIGINT',stop);
