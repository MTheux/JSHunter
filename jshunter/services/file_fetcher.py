"""
JSHunter — File Fetcher Service
HTTP fetch com retry, timeout e headers reais
"""

import time
import requests
import urllib3
from typing import Optional, Tuple

from jshunter.config import BaseConfig, get_config
from jshunter.utils.logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FileFetcher:
    """Servico para download de arquivos JavaScript remotos"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.USER_AGENT,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

    def fetch(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Faz download do conteudo de uma URL.
        Retorna (conteudo, erro_ou_none)
        Com retry automatico em caso de falha.
        """
        url = self._sanitize_url(url)
        timeout = getattr(self.config, 'FETCH_TIMEOUT', 60)
        max_retries = getattr(self.config, 'FETCH_MAX_RETRIES', 2)
        retry_delay = getattr(self.config, 'FETCH_RETRY_DELAY', 2)

        last_error = None

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Fetch attempt {attempt}/{max_retries}: {url[:100]}")
                response = self.session.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    content = response.text
                    size_kb = len(content) / 1024
                    logger.info(f"OK — {size_kb:.1f} KB downloaded")
                    return content, None

                last_error = f"HTTP {response.status_code}"
                logger.warning(f"HTTP {response.status_code} for {url[:80]}")

            except requests.exceptions.Timeout:
                last_error = f"Timeout ({timeout}s)"
                logger.warning(f"Timeout on attempt {attempt}")
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {str(e)[:100]}"
                logger.warning(f"Connection error on attempt {attempt}")
            except Exception as e:
                last_error = f"Unexpected error: {str(e)[:100]}"
                logger.error(f"Unexpected error: {e}")

            if attempt < max_retries:
                logger.info(f"Retrying in {retry_delay}s...")
                time.sleep(retry_delay)

        return None, last_error

    def _sanitize_url(self, url: str) -> str:
        """Corrige URLs comuns"""
        url = url.strip()
        if '0.0.0.0' in url:
            url = url.replace('0.0.0.0', 'localhost')
        return url
