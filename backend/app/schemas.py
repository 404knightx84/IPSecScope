from typing import List, Optional, Dict, Literal
from pydantic import BaseModel

Status = Literal["observed", "inferred", "provided", "not_determinable"]

class Item(BaseModel):
    id: str
    label: str
    value: Optional[str] = None
    status: Status
    confidence: Optional[float] = None
    evidence: List[int] = []
    low_confidence: bool = False
    reason: Optional[str] = None
    advisor: Optional[str] = None

class Traffic(BaseModel):
    status: Status
    value: Optional[str] = None
    confidence: Optional[float] = None
    probabilities: Dict[str, float] = {}
    windows: int = 0
    low_confidence: bool = False
    smoke_model: bool = False
    reason: Optional[str] = None
    advisor: Optional[str] = None

class Score(BaseModel):
    score_min: int
    score_max: int
    risk_level: str
    risk_level_best_case: Optional[str] = None
    floor_applied: bool = False

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    confidence: Optional[float] = None
    evidence: List[int] = []
    fix: str = ""
    reference: Optional[str] = None
    threat: Optional[str] = None

class ThreatEntry(BaseModel):
    id: str
    name: str
    basis: str = ""

class ThreatMatrix(BaseModel):
    likelihood_axis: Dict[str, str] = {}
    impact_axis: Dict[str, str] = {}
    cells: Dict[str, List[ThreatEntry]] = {}

class AnalyzeResponse(BaseModel):
    file: str
    duration_s: float
    ike_packets: int
    esp_packets: int
    items: List[Item]
    traffic: Traffic
    score: Score
    findings: List[Finding]
    threat_matrix: ThreatMatrix
    mock: bool = False
