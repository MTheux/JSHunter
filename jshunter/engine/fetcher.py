"""
JSHunter — Motor 1: Fetcher
Busca, prepara e beautifica conteudo JavaScript
"""

import jsbeautifier
from dataclasses import dataclass
from typing import Optional

from jshunter.config import BaseConfig, get_config
from jshunter.services.file_fetcher import FileFetcher
from jshunter.utils.logger import logger


@dataclass
class FetchedContent:
    """Resultado do Motor 1 — conteudo preparado para analise"""
    url: str
    content: str
    original_size: int
    beautified: bool
    source_map_detected: bool
    source_map_url: str
    error: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.content is not None and self.error is None


class ContentFetcher:
    """Motor 1 — Busca e prepara conteudo JavaScript"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()
        self.file_fetcher = FileFetcher(self.config)
        self.beautifier_opts = jsbeautifier.default_options()
        self.beautifier_opts.indent_size = 2

    def fetch_url(self, url: str) -> FetchedContent:
        """Busca JS de uma URL e prepara o conteudo"""
        content, error = self.file_fetcher.fetch(url)
        if content is None:
            return FetchedContent(
                url=url, content="", original_size=0,
                beautified=False, source_map_detected=False,
                source_map_url="", error=error,
            )

        return self.prepare(url, content)

    def prepare(self, url: str, content: str) -> FetchedContent:
        """Prepara conteudo JS (beautify + source map detection)"""
        original_size = len(content)

        # Detectar source map
        import re
        source_map_detected = False
        source_map_url = ""
        match = re.search(r'//# sourceMappingURL=([^\s]+)', content)
        if match:
            source_map_detected = True
            map_url = match.group(1)
            if not map_url.startswith('http') and 'http' in url:
                base_url = url.rsplit('/', 1)[0]
                map_url = f"{base_url}/{map_url}"
            source_map_url = map_url

        # Beautify se minificado
        beautified = False
        cfg = self.config
        line_threshold = getattr(cfg, 'BEAUTIFY_LINE_THRESHOLD', 5)
        size_threshold = getattr(cfg, 'BEAUTIFY_SIZE_THRESHOLD', 1000)

        if len(content.split('\n')) < line_threshold and len(content) > size_threshold:
            try:
                content = jsbeautifier.beautify(content, self.beautifier_opts)
                beautified = True
                logger.info(f"Content beautified ({original_size} -> {len(content)} bytes)")
            except Exception:
                pass

        # Validar tamanho
        max_size = getattr(cfg, 'MAX_FILE_SIZE', 20 * 1024 * 1024)
        if original_size > max_size:
            size_mb = original_size / (1024 * 1024)
            max_mb = max_size / (1024 * 1024)
            return FetchedContent(
                url=url, content="", original_size=original_size,
                beautified=False, source_map_detected=source_map_detected,
                source_map_url=source_map_url,
                error=f"Arquivo muito grande: {size_mb:.1f}MB (max: {max_mb:.0f}MB)",
            )

        return FetchedContent(
            url=url, content=content, original_size=original_size,
            beautified=beautified, source_map_detected=source_map_detected,
            source_map_url=source_map_url,
        )
