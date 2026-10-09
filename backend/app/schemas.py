from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class Action(Strict):
    tool: str = Field(min_length=1, max_length=80)
    args: dict = Field(default_factory=dict)

class ReadInvoice(Strict):
    invoice_id: str = Field(min_length=1, max_length=40)

class InvoiceFacts(Strict):
    invoice_id: str = Field(min_length=1, max_length=40)
    vendor: str = Field(min_length=1, max_length=200)
    amount: int = Field(ge=0, le=1000000000)
    currency: str = Field(min_length=3, max_length=3)
    due_date: str = Field(min_length=10, max_length=10)

class WriteSummary(ReadInvoice):
    path: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1, max_length=4000)
    facts: InvoiceFacts

class SendEmail(Strict):
    to: str = Field(min_length=1, max_length=254)
    body: str = Field(min_length=1, max_length=4000)

class ExportFile(Strict):
    path: str = Field(min_length=1, max_length=200)
    destination: str = Field(min_length=1, max_length=1000)

TOOLS = {'read_invoice': ReadInvoice, 'write_summary': WriteSummary,
         'send_email': SendEmail, 'export_file': ExportFile}
SCENARIOS = Literal['safe','email_exfiltration','file_exfiltration','unauthorized_invoice']
class RunRequest(Strict):
    scenario: SCENARIOS = 'email_exfiltration'
    protected: bool = True
    agent_mode: Literal['replay','live'] = 'replay'

class TaskRequest(Strict):
    scenario: SCENARIOS = 'safe'

class Proposal(Strict):
    action: Action
    call_id: str = Field(min_length=1, max_length=100)

class EvaluationRequest(Strict):
    agent_mode: Literal['replay','live'] = 'replay'
    scenarios: list[SCENARIOS] = Field(default_factory=lambda: ['safe','email_exfiltration','file_exfiltration','unauthorized_invoice'],min_length=1,max_length=4)
    trials: int = Field(default=1,ge=1,le=3)
