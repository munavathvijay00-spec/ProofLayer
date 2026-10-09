const path=require('path');
const {chromium}=require(require.resolve('playwright',{paths:[path.join(__dirname,'..','frontend'),process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES||process.cwd()]}));
const {spawn}=require('child_process');
const fs=require('fs');
const root=path.resolve(__dirname,'..');
const backend=spawn('python3',['-m','uvicorn','app.main:app','--port','8000'],{cwd:path.join(root,'backend'),stdio:'pipe',detached:true,env:{...process.env,DB_PATH:path.join(root,'evidence','ui-test.db')}});
const frontend=spawn('npm',['run','start','--','--hostname','127.0.0.1'],{cwd:path.join(root,'frontend'),stdio:'pipe',detached:true});
let browser;
frontend.stdout.on('data',d=>process.stdout.write(d));frontend.stderr.on('data',d=>process.stderr.write(d));backend.stderr.on('data',d=>process.stderr.write(d));
async function ready(url){for(let i=0;i<80;i++){try{const r=await fetch(url);if(r.ok)return}catch{}await new Promise(r=>setTimeout(r,150));}throw Error('Server startup failed: '+url)}
(async()=>{try{
 await Promise.all([ready('http://localhost:8000/health'),ready('http://localhost:3000')]);
 browser=await chromium.launch({headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000');
 await page.getByText('API connected',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Run protected',exact:true}).click();
 await page.getByRole('heading',{name:'Blocked before execution'}).waitFor();
 await page.getByText('Verified summary saved',{exact:true}).waitFor();
 await page.screenshot({path:path.join(root,'evidence','console-desktop.png'),fullPage:true});
 await page.getByRole('button',{name:'Run baseline',exact:true}).click();
 await page.getByRole('heading',{name:'Unauthorized effect recorded'}).waitFor();
 await page.getByRole('button',{name:'Run evaluation',exact:true}).click();
 await page.getByRole('button',{name:'Download evaluation evidence'}).waitFor();
 const text=await page.locator('main').innerText();if(!text.includes('3/3')||!text.includes('8/8'))throw Error('Measured suite metrics missing');
 await page.getByRole('button',{name:'Policy',exact:true}).click();
 await page.getByRole('heading',{name:'Server-controlled task permissions'}).waitFor();
 await page.getByRole('button',{name:'Audit trail',exact:true}).click();
 await page.getByRole('heading',{name:'Every decision, accounted for.'}).waitFor();
 await page.getByRole('button',{name:'Lab',exact:true}).click();
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:path.join(root,'evidence','console-mobile.png'),fullPage:true});
 const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth);if(overflow)throw Error('Mobile page has horizontal overflow');
 if(errors.length)throw Error('Browser errors: '+errors.join('; '));
 const report={status:'passed',checks:['API connection','Protected attack denied and summary persisted','Baseline unauthorized effect recorded','Evaluation 3/3 blocked and 8/8 completed','Policy and audit navigation','390px viewport without page overflow','No uncaught browser errors']};
 fs.writeFileSync(path.join(root,'evidence','ui-smoke.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
 }finally{if(browser)await browser.close();for(const child of [frontend,backend]){try{process.kill(-child.pid,'SIGTERM')}catch{}}}
})().catch(e=>{console.error(e);process.exitCode=1});
