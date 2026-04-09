"""
JSHunter — Models
Dataclasses de resultado da analise
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class AnalysisResult:
    """Estrutura completa do resultado de uma analise"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    high_entropy_strings: List[Dict[str, Any]]
    source_map_detected: bool
    source_map_url: str
    errors: List[str]
    file_size: int
    analysis_timestamp: str
    analysis_engine: str
    risk_score: int
    severity_counts: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionario serializavel"""
        return {
            'url': self.url,
            'api_keys': self.api_keys,
            'credentials': self.credentials,
            'emails': self.emails,
            'interesting_comments': self.interesting_comments,
            'xss_vulnerabilities': self.xss_vulnerabilities,
            'xss_functions': self.xss_functions,
            'api_endpoints': self.api_endpoints,
            'parameters': self.parameters,
            'paths_directories': self.paths_directories,
            'high_entropy_strings': self.high_entropy_strings,
            'source_map_detected': self.source_map_detected,
            'source_map_url': self.source_map_url,
            'errors': self.errors,
            'file_size': self.file_size,
            'analysis_timestamp': self.analysis_timestamp,
            'analysis_engine': self.analysis_engine,
            'risk_score': self.risk_score,
            'severity_counts': self.severity_counts,
        }

    @property
    def total_findings(self) -> int:
        return (
            len(self.api_keys) + len(self.credentials) +
            len(self.xss_vulnerabilities) + len(self.high_entropy_strings)
        )

    @property
    def has_critical(self) -> bool:
        return self.severity_counts.get('critical', 0) > 0


def empty_result(url: str, errors: List[str] = None) -> AnalysisResult:
    """Cria um resultado vazio (usado em falhas)"""
    from datetime import datetime
    return AnalysisResult(
        url=url, api_keys=[], credentials=[], emails=[],
        interesting_comments=[], xss_vulnerabilities=[], xss_functions=[],
        api_endpoints=[], parameters=[], paths_directories=[],
        high_entropy_strings=[], source_map_detected=False,
        source_map_url="", errors=errors or [], file_size=0,
        analysis_timestamp=datetime.now().isoformat(),
        analysis_engine="None", risk_score=0,
        severity_counts={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
    )
