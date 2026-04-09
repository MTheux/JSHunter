"""
JSHunter — Motor 2: Extractor
Extrai findings brutos via AST + Regex + Entropia
"""

import re
from typing import List, Dict, Any, Optional

from jshunter.config import BaseConfig, get_config
from jshunter.engine.ast_visitor import ASTVisitor
from jshunter.engine.entropy import find_high_entropy_strings
from jshunter.engine import patterns as P
from jshunter.utils.logger import logger

import esprima


class FindingsExtractor:
    """Motor 2 — Extrai todos os findings brutos do JavaScript"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()

    def extract(self, content: str, url: str) -> Dict[str, Any]:
        """
        Extrai findings brutos do conteudo JS.
        Retorna dict com todas as categorias + metadados do motor.
        """
        # --- PHASE 1: AST ---
        ast_findings = self._analyze_ast(content)
        ast_success = ast_findings is not None

        credentials = []
        xss_vulns = []

        if ast_findings:
            credentials.extend(ast_findings['credentials'])
            xss_vulns.extend(ast_findings['xss'])
            xss_vulns.extend(ast_findings.get('dangerous_functions', []))
            if ast_findings['frameworks']:
                for fw in ast_findings['frameworks']:
                    xss_vulns.append({
                        'type': 'Framework Detected',
                        'match': f'{fw} structure identified',
                        'line': 1,
                        'severity': 'info',
                    })

        # --- PHASE 2: REGEX ---
        api_keys = self._find_patterns(content, P.API_KEY_PATTERNS)
        credentials.extend(self._find_patterns(content, P.CREDENTIAL_PATTERNS))
        emails = self._find_patterns(content, P.EMAIL_PATTERNS)
        comments = self._find_patterns(content, P.COMMENT_PATTERNS)

        # XSS fallback
        if not ast_findings or (not xss_vulns and not credentials):
            xss_vulns.extend(self._find_patterns(content, P.XSS_PATTERNS_FALLBACK))

        # Prototype pollution
        xss_vulns.extend(self._find_patterns(content, P.PROTOTYPE_POLLUTION_PATTERNS))

        # SSRF / Open Redirect
        xss_vulns.extend(self._find_patterns(content, P.SSRF_REDIRECT_PATTERNS))

        # Sensitive URLs
        api_keys.extend(self._find_patterns(content, P.SENSITIVE_URL_PATTERNS))

        # Endpoints
        api_endpoints = self._find_patterns(content, P.API_ENDPOINT_PATTERNS)
        parameters = self._find_patterns(content, P.PARAMETER_PATTERNS)
        paths = self._find_patterns(content, P.PATH_PATTERNS)

        # --- PHASE 3: ENTROPY ---
        high_entropy = find_high_entropy_strings(
            content, getattr(self.config, 'ENTROPY_THRESHOLD', 4.5)
        )

        # --- FILTER FALSE POSITIVES ---
        credentials = self._filter_credential_false_positives(credentials)

        # Marcar raw_severity em todos os findings de seguranca
        all_security = api_keys + credentials + xss_vulns + high_entropy
        for finding in all_security:
            finding['raw_severity'] = finding.get('severity', 'info')

        engine = 'AST + Regex' if ast_success else 'Regex Only'
        logger.info(f"Extraction complete — Engine: {engine} | "
                    f"Keys: {len(api_keys)} | Creds: {len(credentials)} | "
                    f"XSS: {len(xss_vulns)} | Entropy: {len(high_entropy)} | "
                    f"Endpoints: {len(api_endpoints)}")

        return {
            'api_keys': api_keys,
            'credentials': credentials,
            'emails': emails,
            'interesting_comments': comments,
            'xss_vulnerabilities': xss_vulns,
            'api_endpoints': api_endpoints,
            'parameters': parameters,
            'paths_directories': paths,
            'high_entropy_strings': high_entropy,
            'engine': engine,
        }

    def _analyze_ast(self, content: str) -> Optional[Dict[str, List]]:
        """Executa analise AST com Esprima"""
        visitor = ASTVisitor()
        try:
            try:
                tree = esprima.parseScript(content, {'loc': True, 'tolerant': True})
            except Exception:
                tree = esprima.parseModule(content, {'loc': True, 'tolerant': True})
            visitor.visit(tree)
            return visitor.findings
        except Exception:
            return None

    def _find_patterns(self, content: str, pattern_list: List[tuple],
                       context_lines: int = 5) -> List[Dict[str, Any]]:
        """Busca padroes regex no conteudo com contexto expandido (5 linhas para IA)"""
        findings = []
        lines = content.split('\n')
        seen = set()

        for pattern_info in pattern_list:
            pattern = pattern_info[0]
            label = pattern_info[1]
            severity = pattern_info[2] if len(pattern_info) > 2 else 'info'

            try:
                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    match_text = match.group(0)[:150]

                    dedup_key = (label, line_num)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                    start_ctx = max(0, line_num - context_lines - 1)
                    end_ctx = min(len(lines), line_num + context_lines)

                    findings.append({
                        'type': label,
                        'match': match_text,
                        'line': line_num,
                        'line_content': line_content,
                        'context': '\n'.join(lines[start_ctx:end_ctx]),
                        'severity': severity,
                    })
            except Exception:
                continue
        return findings

    def _filter_credential_false_positives(self, credentials: List[Dict]) -> List[Dict]:
        """Filtra falsos positivos de credenciais (labels, placeholders, constantes)"""
        filtered = []
        for cred in credentials:
            match_text = cred.get('match', '')

            value = match_text
            for sep in ['=', ':']:
                if sep in match_text:
                    value = match_text.split(sep, 1)[1].strip()
                    break

            value_clean = value.strip().strip('"').strip("'").strip('`').strip()

            if value_clean.lower() in P.CREDENTIAL_FALSE_POSITIVES:
                continue

            is_label = False
            for label_pattern in P.CREDENTIAL_LABEL_PATTERNS:
                if re.match(label_pattern, value_clean):
                    is_label = True
                    break
            if is_label:
                continue

            if len(value_clean) <= 3 or value_clean in ('true', 'false', 'null', 'none', 'undefined'):
                continue

            filtered.append(cred)
        return filtered
