"""
JSHunter — Analysis Engine (Orchestrator)
Orquestra os 3 motores: Fetcher → Extractor → AI Classifier
"""

from typing import Dict, Any
from datetime import datetime

from jshunter.config import BaseConfig, get_config
from jshunter.models.results import AnalysisResult
from jshunter.engine.fetcher import ContentFetcher, FetchedContent
from jshunter.engine.extractor import FindingsExtractor
from jshunter.engine.ai_classifier import AIClassifier
from jshunter.utils.logger import logger


class JavaScriptAnalyzer:
    """JSHunter — Orquestra Motor 1 (Fetcher) + Motor 2 (Extractor) + Motor 3 (AI)"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()
        self.fetcher = ContentFetcher(self.config)
        self.extractor = FindingsExtractor(self.config)
        self.ai_classifier = AIClassifier(self.config)

    def analyze(self, url: str, content: str) -> AnalysisResult:
        """
        Executa pipeline completo de analise.
        Content ja vem pre-fetched (via service layer ou direto).
        """
        file_size = len(content)

        # --- MOTOR 1: Prepare content ---
        fetched = self.fetcher.prepare(url, content)

        if not fetched.is_valid:
            return self._empty_result(url, file_size, [fetched.error])

        # --- MOTOR 2: Extract findings ---
        raw_findings = self.extractor.extract(fetched.content, url)

        # --- MOTOR 3: AI Classification ---
        classified = self.ai_classifier.classify(raw_findings)

        # --- BUILD RESULT ---
        engine = classified.get('engine', 'Regex Only')
        if classified.get('ai_classified'):
            engine += ' + AI'

        all_security = (
            classified['api_keys'] +
            classified['credentials'] +
            classified['xss_vulnerabilities'] +
            classified['high_entropy_strings']
        )
        severity_counts = self._count_severities(all_security)
        risk_score = self._calculate_risk_score(severity_counts)

        return AnalysisResult(
            url=url,
            api_keys=classified['api_keys'],
            credentials=classified['credentials'],
            emails=classified['emails'],
            interesting_comments=classified['interesting_comments'],
            xss_vulnerabilities=classified['xss_vulnerabilities'],
            xss_functions=[],
            api_endpoints=classified['api_endpoints'],
            parameters=classified['parameters'],
            paths_directories=classified['paths_directories'],
            high_entropy_strings=classified['high_entropy_strings'],
            source_map_detected=fetched.source_map_detected,
            source_map_url=fetched.source_map_url,
            errors=[],
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat(),
            analysis_engine=engine,
            risk_score=risk_score,
            severity_counts=severity_counts,
        )

    def _count_severities(self, findings: list) -> Dict[str, int]:
        """Conta findings por severidade"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = str(f.get('severity', 'info')).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calcula risk score 0-100"""
        score = 0
        score += severity_counts.get('critical', 0) * 25
        score += severity_counts.get('high', 0) * 15
        score += severity_counts.get('medium', 0) * 8
        score += severity_counts.get('low', 0) * 3
        score += severity_counts.get('info', 0) * 1
        return min(score, 100)

    def _empty_result(self, url: str, file_size: int, errors: list) -> AnalysisResult:
        """Resultado vazio para erros"""
        from jshunter.models.results import empty_result
        result = empty_result(url, errors)
        result.file_size = file_size
        return result
