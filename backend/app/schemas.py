from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class Action(Strict):
    tool: str = Field(min_length=1, max_length=80)
    args: dict = Field(default_factory=dict)

class ReadInvoice(Strict):
    invoice_id: str = Field(min_length=1, max_length=40, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*$')

class InvoiceFacts(Strict):
    invoice_id: str = Field(min_length=1, max_length=40, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
    vendor: str = Field(min_length=1, max_length=200)
    amount: int | float = Field(ge=0, le=1000000000, allow_inf_nan=False)
    currency: str = Field(pattern=r'^[A-Z]{3}$')
    due_date: str = Field(min_length=10, max_length=10)

    @field_validator('due_date')
    @classmethod
    def valid_date(cls, value):
        from datetime import date
        date.fromisoformat(value)
        return value

class InvoiceImport(Strict):
    confirmed: Literal[True]
    facts: InvoiceFacts
    content: str = Field(min_length=1, max_length=30000)
    filename: str = Field(default='Pasted invoice', min_length=1, max_length=200)

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
    document_id: str | None = Field(default=None, max_length=36)
    scenario: SCENARIOS = 'email_exfiltration'
    protected: bool = True
    agent_mode: Literal['replay','live'] = 'replay'

class TaskRequest(Strict):
    document_id: str | None = Field(default=None, max_length=36)
    scenario: SCENARIOS = 'safe'

class Proposal(Strict):
    action: Action
    call_id: str = Field(min_length=1, max_length=100)

class EvaluationRequest(Strict):
    document_id: str | None = Field(default=None, max_length=36)
    agent_mode: Literal['replay','live'] = 'replay'
    scenarios: list[SCENARIOS] = Field(default_factory=lambda: ['safe','email_exfiltration','file_exfiltration','unauthorized_invoice'],min_length=1,max_length=4)
    trials: int = Field(default=1,ge=1,le=3)
