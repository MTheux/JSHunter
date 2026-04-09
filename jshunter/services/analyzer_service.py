"""
JSHunter — Analyzer Service
Orquestra o fluxo completo: fetch → analyze → result
"""

from typing import Optional

from jshunter.config import BaseConfig, get_config
from jshunter.engine.analyzer import JavaScriptAnalyzer
from jshunter.engine.fetcher import ContentFetcher
from jshunter.models.results import AnalysisResult, empty_result
from jshunter.utils.logger import logger


class AnalyzerService:
    """Servico de alto nivel que orquestra fetch + analise (3 motores)"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()
        self.analyzer = JavaScriptAnalyzer(self.config)
        self.content_fetcher = ContentFetcher(self.config)

    def analyze_url(self, url: str) -> AnalysisResult:
        """Analisa um arquivo JavaScript a partir de uma URL"""
        logger.info(f"Analyzing URL: {url[:100]}")

        # Motor 1: Fetch
        fetched = self.content_fetcher.fetch_url(url)
        if not fetched.is_valid:
            logger.error(f"Failed to fetch: {fetched.error}")
            return empty_result(url, [f"Failed to fetch: {fetched.error}"])

        # Motor 2 + 3: Extract + AI (via analyzer)
        return self._run_analysis(url, fetched.content)

    def analyze_content(self, url: str, content: str) -> AnalysisResult:
        """Analisa conteudo JavaScript direto (upload ou pre-fetched)"""
        max_size = getattr(self.config, 'MAX_FILE_SIZE', 20 * 1024 * 1024)
        if len(content) > max_size:
            size_mb = len(content) / (1024 * 1024)
            max_mb = max_size / (1024 * 1024)
            logger.warning(f"File too large: {size_mb:.1f}MB (max: {max_mb:.0f}MB)")
            return empty_result(url, [f"Arquivo muito grande: {size_mb:.1f}MB (max: {max_mb:.0f}MB)"])

        return self._run_analysis(url, content)

    def _run_analysis(self, url: str, content: str) -> AnalysisResult:
        """Executa analise completa (Motor 2 + Motor 3)"""
        try:
            result = self.analyzer.analyze(url, content)
            logger.info(
                f"Done — Risk: {result.risk_score}/100 | "
                f"Findings: {result.total_findings} | "
                f"Engine: {result.analysis_engine}"
            )
            return result
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return empty_result(url, [f"Erro na analise: {str(e)[:200]}"])
