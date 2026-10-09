from dataclasses import dataclass
from pydantic import ValidationError
from .schemas import Action, TOOLS

POLICY = {
    'version': 'invoice-v1',
    'read_invoice': {'invoice_ids': ['INV-001']},
    'write_summary': {'paths': ['/workspace/summary.json'], 'invoice_ids': ['INV-001']},
    'send_email': {'recipients': ['finance@company.test']},
    'export_file': {'destinations': [], 'paths': ['/workspace/invoices/INV-001.pdf']},
}
@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    reason: str

def evaluate(action: Action, policy: dict = POLICY) -> Decision:
    schema = TOOLS.get(action.tool)
    if schema is None:
        return Decision(False, 'UNKNOWN_TOOL', 'Tool is absent from the server registry')
    try:
        args = schema.model_validate(action.args)
    except ValidationError:
        return Decision(False, 'INVALID_ARGUMENTS', 'Tool arguments do not match the strict schema')
    grant = policy.get(action.tool)
    if not isinstance(grant, dict):
        return Decision(False, 'NO_GRANT', 'No task permission for this tool')
    if action.tool == 'read_invoice':
        ok = args.invoice_id in grant.get('invoice_ids', [])
        return Decision(ok, 'INVOICE_SCOPE', 'Invoice is within task scope' if ok else 'Invoice is outside the task document scope')
    if action.tool == 'write_summary':
        ok = args.path in grant.get('paths', []) and args.invoice_id in grant.get('invoice_ids', [])
        return Decision(ok, 'SUMMARY_SCOPE', 'Approved summary path and source invoice' if ok else 'Summary path or source invoice is not authorized')
    if action.tool == 'send_email':
        ok = args.to in grant.get('recipients', [])
        return Decision(ok, 'RECIPIENT_ALLOWLIST', 'Recipient is explicitly approved' if ok else 'Recipient is not in the task allowlist')
    ok = args.destination in grant.get('destinations', []) and args.path in grant.get('paths', [])
    return Decision(ok, 'EXPORT_DESTINATION', 'Export is explicitly approved' if ok else 'No permission to transfer this file to the proposed destination')
