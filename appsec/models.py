from typing import Literal

from pydantic import BaseModel, ConfigDict


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Repository(Record):
    slug: str
    lockfile: str
    revision: str


class Registry(Record):
    host: str | None
    source: Literal["public-npm", "other-registry", "unsupported"]


class Dependency(Record):
    name: str
    version: str
    path: str
    type: Literal["production", "development", "optional", "peer"]
    registry: Registry
    edges: dict[str, str]
    direct: bool


class Inventory(Record):
    repository: Repository
    dependencies: list[Dependency]


class Advisory(Record):
    id: str
    aliases: list[str]
    modified: str
    summary: str
    conditions_text: str = ""
    references: list[str]
    severity: list[dict[str, str]]
    affected: list[dict]
    provenance: str


class Finding(Record):
    finding_id: str
    ecosystem: Literal["npm"] = "npm"
    package: str
    installed_version: str
    dependency_paths: list[str]
    advisory_ids: list[str]
    severity: str
    fix_versions: list[str]
    references: list[str]
    advisories: list[Advisory]


class Evidence(Record):
    id: str
    path: str
    line: int
    kind: str = "text mention"
    text: str


class Observation(Record):
    status: Literal["supported", "contradicted", "unknown"]
    assessment: str
    evidence_ids: list[str]


class Assessment(Record):
    prerequisites: Observation
    reachability: Observation
    input_exposure: Observation
    controls_and_limits: str
    impact: str
    priority: Literal["urgent", "high", "normal", "low", "investigate"]
    priority_reason: str
    missing_evidence: list[str]
    classification: Literal["confirmed affected", "potentially affected",
                            "not affected", "unknown"]
    reasoning: str
    evidence_ids: list[str]
    confidence: Literal["low", "medium", "high"]
    next_action: str


class Investigation(Record):
    reasoning: str
    evidence_ids: list[str]
    recommendation: Literal["review existing tests", "human review", "inconclusive"]


class TestProposal(Record):
    behavior: str
    expected_result: str
    evidence_ids: list[str]


class RemediationAdvice(Record):
    recommendation: Literal["upgrade", "escalate"]
    reasoning: str
    compatibility_risks: str
    evidence_ids: list[str]


class Narrative(Record):
    exposure: str
    rationale: str
    residual_risks: str
    evidence_ids: list[str]


class AgentExecution(Record):
    role: str
    input_digest: str
    model: str
    attempts: int
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    outcome: str


class ExposureValidation(Record):
    result: Literal["unable to validate", "not applicable"]
    evidence_ids: list[str]
    checks: list[str]


class Validation(Record):
    result: Literal["pass", "fail", "inconclusive"]
    checks: list[str]


class Attempt(Record):
    version: str
    validation: Validation


class PullRequest(Record):
    number: int
    url: str
    branch: str


class Transition(Record):
    finding_id: str
    before: str | None
    after: str
    reason: str
