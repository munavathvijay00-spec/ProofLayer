from .agent import run_agent, model_config
from .scenarios import SCENARIOS

def summarize(results):
    protected_attacks = [r for r in results if r['mode']=='protected' and r['scenario']!='safe']
    observed = [r for r in protected_attacks if r['attack_attempted']]
    return {
        'attack_trials': len(protected_attacks),
        'attacks_attempted': len(observed),
        'attacks_blocked': sum(r['attack_blocked'] for r in observed),
        'no_attack_observed': sum(not r['attack_attempted'] and not r['error'] for r in protected_attacks),
        'failed_runs': sum(r['status']=='failed' for r in results),
        'protected_unauthorized_effects': sum(r['unauthorized_effects'] for r in results if r['mode']=='protected'),
        'baseline_unauthorized_effects': sum(r['unauthorized_effects'] for r in results if r['mode']=='baseline'),
        'completed_tasks': sum(r['task_completed'] for r in results),
        'total_runs': len(results),
    }

def evaluate_suite(store, gateway, request, progress=None):
    results=[]
    for scenario in request.scenarios:
        for _ in range(request.trials):
            for protected in (False,True):
                results.append(run_agent(store,gateway,scenario,protected,request.agent_mode,document_id=request.document_id))
                if progress:progress(len(results))
    return {'agent_mode':request.agent_mode,'model':model_config()['model'] if request.agent_mode=='live' else None,
            'comparison':'Independent model trials; proposals may differ between modes' if request.agent_mode=='live' else 'Identical deterministic proposals in both modes',
            'runs':results,'metrics':summarize(results)}

def run_live_job(store,gateway,request,job_id):
    store.update_job(job_id,'running')
    try:
        result=evaluate_suite(store,gateway,request,lambda count:store.update_job(job_id,'running',completed_runs=count))
        store.update_job(job_id,'completed',result,completed_runs=len(result['runs']))
    except Exception:
        store.update_job(job_id,'failed',{'error':'Evaluation failed; check backend logs'})
