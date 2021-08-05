from pydantic import BaseModel
from typing import Optional, List

class VulnModel(BaseModel):
    name: str
    severity: str
    desc: Optional[str]


class HostReportModel(BaseModel):
    ip: str
    os: Optional[str]
    threat_score: float
    vulns: Optional[List[VulnModel]]


class HostFullModel(BaseModel):
    name: str
    area: str
    vuln_report: Optional[HostReportModel]

class TargetModel(BaseModel):
    ip: str
    name: str
    area: Optional[str]