"""
JSHunter — Spider Engine
Browser headless (Playwright) para descoberta automatica de JS
Crawl leve: pagina inicial + 1 nivel de links internos
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Set, Optional
from urllib.parse import urlparse, urljoin

from jshunter.utils.logger import logger


# Libs conhecidas que nao vale analisar (fingerprints no nome do arquivo)
KNOWN_LIBS = {
    'jquery', 'react', 'react-dom', 'angular', 'vue', 'lodash', 'underscore',
    'bootstrap', 'popper', 'moment', 'axios', 'd3', 'chart', 'three',
    'socket.io', 'backbone', 'ember', 'handlebars', 'mustache', 'knockout',
    'polymer', 'mootools', 'prototype', 'dojo', 'ext-all', 'sencha',
    'modernizr', 'normalize', 'polyfill', 'core-js', 'regenerator',
    'whatwg-fetch', 'zone.js', 'rxjs', 'tslib',
    'google-analytics', 'gtag', 'gtm', 'analytics', 'hotjar', 'segment',
    'facebook', 'fbevents', 'pixel', 'twitter', 'linkedin',
    'recaptcha', 'grecaptcha', 'turnstile', 'hcaptcha',
    'cdn.jsdelivr', 'cdnjs.cloudflare', 'unpkg.com',
}

# Min/Max size para considerar um JS relevante
MIN_JS_SIZE = 500       # bytes — ignora tracking pixels
MAX_JS_SIZE = 20_000_000  # 20MB


@dataclass
class DiscoveredScript:
    """Um arquivo JS descoberto pelo Spider"""
    url: str
    content: str
    size: int
    source_page: str  # pagina onde foi encontrado


@dataclass
class SpiderResult:
    """Resultado do crawl"""
    target_url: str
    pages_crawled: int = 0
    scripts_found: int = 0
    scripts_ignored: int = 0
    scripts: List[DiscoveredScript] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class SpiderEngine:
    """Spider com Playwright — descobre JS via interceptacao de rede"""

    def __init__(self, max_pages: int = 15, timeout: int = 15000):
        self.max_pages = max_pages
        self.timeout = timeout  # timeout por pagina em ms

    def crawl(self, url: str) -> SpiderResult:
        """Entry point sincrono — roda o async internamente"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._crawl_async(url))
            loop.close()
            return result
        except Exception as e:
            logger.error(f"Spider error: {e}")
            result = SpiderResult(target_url=url)
            result.errors.append(f"Spider error: {str(e)[:200]}")
            return result

    async def _crawl_async(self, url: str) -> SpiderResult:
        """Crawl assincrono com Playwright"""
        from playwright.async_api import async_playwright

        result = SpiderResult(target_url=url)
        parsed = urlparse(url)
        base_domain = self._get_base_domain(parsed.hostname or '')

        seen_scripts: Set[str] = set()
        seen_pages: Set[str] = set()
        scripts: List[DiscoveredScript] = []

        logger.info(f"Spider starting: {url} (domain: {base_domain})")

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
            )
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            # --- Fase 1: Pagina principal ---
            logger.info(f"[Spider] Phase 1: Loading main page")
            page_scripts, internal_links = await self._visit_page(
                context, url, base_domain, seen_scripts
            )
            scripts.extend(page_scripts)
            seen_pages.add(url)
            result.pages_crawled = 1

            logger.info(f"[Spider] Phase 1 done: {len(page_scripts)} JS found, "
                        f"{len(internal_links)} internal links")

            # --- Fase 2: Seguir links internos (1 nivel) ---
            links_to_visit = []
            for link in internal_links:
                if link not in seen_pages and len(links_to_visit) < self.max_pages:
                    links_to_visit.append(link)

            if links_to_visit:
                logger.info(f"[Spider] Phase 2: Visiting {len(links_to_visit)} internal links")

            for i, link in enumerate(links_to_visit):
                try:
                    logger.info(f"[Spider] [{i+1}/{len(links_to_visit)}] {link[:80]}")
                    page_scripts, _ = await self._visit_page(
                        context, link, base_domain, seen_scripts
                    )
                    scripts.extend(page_scripts)
                    seen_pages.add(link)
                    result.pages_crawled += 1
                except Exception as e:
                    logger.warning(f"[Spider] Failed to visit {link[:60]}: {e}")

            await browser.close()

        result.scripts = scripts
        result.scripts_found = len(scripts)

        logger.info(f"[Spider] Done: {result.pages_crawled} pages, "
                    f"{result.scripts_found} JS files found")

        return result

    async def _visit_page(self, context, url: str, base_domain: str,
                          seen_scripts: Set[str]):
        """Visita uma pagina, intercepta JS e coleta links internos"""
        scripts = []
        js_responses = []

        page = await context.new_page()

        # Interceptar responses de JS
        async def on_response(response):
            try:
                resp_url = response.url
                if self._is_js_response(response, resp_url):
                    js_responses.append((resp_url, response))
            except Exception:
                pass

        page.on('response', on_response)

        try:
            await page.goto(url, wait_until='networkidle', timeout=self.timeout)
        except Exception as e:
            # Timeout nao e fatal — pode ter JS ja carregado
            logger.warning(f"[Spider] Page load issue: {str(e)[:80]}")

        # Processar JS interceptados
        for js_url, response in js_responses:
            if js_url in seen_scripts:
                continue

            # Filtro de dominio
            if not self._is_same_domain(js_url, base_domain):
                continue

            # Filtro de libs conhecidas
            if self._is_known_lib(js_url):
                continue

            try:
                body = await response.text()
                size = len(body)

                if size < MIN_JS_SIZE or size > MAX_JS_SIZE:
                    continue

                seen_scripts.add(js_url)
                scripts.append(DiscoveredScript(
                    url=js_url,
                    content=body,
                    size=size,
                    source_page=url,
                ))
            except Exception:
                continue

        # Coletar links internos
        internal_links = set()
        try:
            links = await page.eval_on_selector_all(
                'a[href]',
                'elements => elements.map(e => e.href)'
            )
            for link in links:
                if link and self._is_same_domain(link, base_domain):
                    # Limpar fragment e query
                    clean = link.split('#')[0].split('?')[0]
                    if clean and clean != url:
                        internal_links.add(clean)
        except Exception:
            pass

        await page.close()
        return scripts, internal_links

    def _is_js_response(self, response, url: str) -> bool:
        """Verifica se a response eh um arquivo JavaScript"""
        content_type = response.headers.get('content-type', '')
        if 'javascript' in content_type or 'ecmascript' in content_type:
            return True
        if re.search(r'\.js(\?|$)', url):
            return True
        return False

    def _is_same_domain(self, url: str, base_domain: str) -> bool:
        """Verifica se URL pertence ao mesmo dominio ou subdominios"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
            return hostname == base_domain or hostname.endswith('.' + base_domain)
        except Exception:
            return False

    def _is_known_lib(self, url: str) -> bool:
        """Verifica se eh uma lib conhecida que nao vale analisar"""
        url_lower = url.lower()
        for lib in KNOWN_LIBS:
            if lib in url_lower:
                return True
        return False

    def _get_base_domain(self, hostname: str) -> str:
        """Extrai dominio base (ex: app.target.com -> target.com)"""
        parts = hostname.split('.')
        if len(parts) >= 2:
            # Handle co.uk, com.br etc
            if parts[-2] in ('co', 'com', 'org', 'net', 'gov', 'edu') and len(parts) >= 3:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return hostname
