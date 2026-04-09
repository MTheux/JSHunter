"""
JSHunter — Motor 3: AI Classifier
Classifica findings usando Groq/Llama 3 para precisao maxima
"""

import json
import re
from typing import List, Dict, Any, Optional

from jshunter.config import BaseConfig, get_config
from jshunter.utils.logger import logger


CLASSIFICATION_PROMPT = """You are an expert JavaScript security analyst. Analyze the following findings extracted from a JavaScript file and classify each one accurately.

For each finding, determine:
1. **severity**: critical, high, medium, low, info, or false_positive
2. **reason**: A brief explanation in Portuguese (BR) of why you classified it this way

Classification guidelines:
- **critical**: Real exposed secrets (API keys with valid format, hardcoded passwords with actual values, database connection strings with real credentials)
- **high**: Dangerous patterns that could be exploited (DOM XSS sinks with user input, eval with dynamic content, prototype pollution)
- **medium**: Potentially dangerous patterns that need context (innerHTML usage, postMessage without origin check)
- **low**: Minor issues or best practice violations (console.log with sensitive data, TODO/FIXME security comments)
- **info**: Informational findings (framework detection, endpoint discovery, email addresses)
- **false_positive**: Not a real finding (UI labels like "Password:", placeholder text, form field names, variable names that match patterns but aren't secrets, common constants)

IMPORTANT: Be strict about false positives. Things like:
- `password = "Password"` or `password = "confirm password"` are UI labels, NOT leaked credentials
- `API_KEY = ""` or `token = "YOUR_TOKEN_HERE"` are placeholders, NOT real secrets
- Variable names like `passwordField`, `apiKeyInput` are code identifiers, NOT secrets
- Generic values like `test`, `example`, `demo`, `sample` are NOT real credentials

Respond ONLY with a valid JSON array. No markdown, no explanation outside the JSON.

FINDINGS TO ANALYZE:
{findings_text}

RESPOND WITH THIS EXACT FORMAT:
[
  {{"id": 0, "severity": "critical", "reason": "Chave AWS real exposta no codigo client-side"}},
  {{"id": 1, "severity": "false_positive", "reason": "Label de formulario, nao credencial real"}}
]"""


class AIClassifier:
    """Motor 3 — Classifica findings com Groq/Llama 3"""

    def __init__(self, config: BaseConfig = None):
        self.config = config or get_config()
        self.api_key = getattr(self.config, 'GROQ_API_KEY', '')
        self.model = getattr(self.config, 'GROQ_MODEL', 'llama-3.3-70b-versatile')
        self.timeout = getattr(self.config, 'AI_TIMEOUT', 30)
        self.batch_size = getattr(self.config, 'AI_BATCH_SIZE', 30)
        self._client = None

    @property
    def is_available(self) -> bool:
        """Checa se a IA esta configurada e disponivel"""
        enabled = getattr(self.config, 'AI_ENABLED', True)
        return bool(self.api_key) and enabled

    def _get_client(self):
        """Lazy init do cliente Groq"""
        if self._client is None:
            try:
                from groq import Groq
                self._client = Groq(api_key=self.api_key)
            except ImportError:
                logger.error("groq package not installed. Run: pip install groq")
                return None
            except Exception as e:
                logger.error(f"Failed to init Groq client: {e}")
                return None
        return self._client

    def classify(self, raw_findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifica findings com IA.
        Recebe o dict do Motor 2, retorna o mesmo dict com severidades atualizadas.
        Se IA nao disponivel, retorna findings sem modificacao.
        """
        if not self.is_available:
            logger.info("AI not available — using raw severities (Motor 2 only)")
            return raw_findings

        # Coletar todos os findings de seguranca para classificar
        security_categories = ['api_keys', 'credentials', 'xss_vulnerabilities', 'high_entropy_strings']
        all_security = []
        finding_map = []  # (category, index) para mapear de volta

        for category in security_categories:
            findings = raw_findings.get(category, [])
            for i, finding in enumerate(findings):
                all_security.append(finding)
                finding_map.append((category, i))

        if not all_security:
            logger.info("No security findings to classify")
            return raw_findings

        logger.info(f"Classifying {len(all_security)} findings with AI ({self.model})")

        # Processar em batches
        classifications = []
        for batch_start in range(0, len(all_security), self.batch_size):
            batch = all_security[batch_start:batch_start + self.batch_size]
            batch_result = self._classify_batch(batch, batch_start)
            classifications.extend(batch_result)

        # Aplicar classificacoes de volta
        false_positive_count = 0
        for idx, classification in enumerate(classifications):
            if idx >= len(finding_map):
                break

            category, finding_idx = finding_map[idx]
            findings_list = raw_findings[category]

            if finding_idx >= len(findings_list):
                continue

            new_severity = classification.get('severity', findings_list[finding_idx].get('raw_severity', 'info'))
            reason = classification.get('reason', '')

            if new_severity == 'false_positive':
                false_positive_count += 1
                findings_list[finding_idx]['severity'] = 'false_positive'
                findings_list[finding_idx]['ai_reason'] = reason
                findings_list[finding_idx]['ai_verified'] = True
            else:
                findings_list[finding_idx]['severity'] = new_severity
                findings_list[finding_idx]['ai_reason'] = reason
                findings_list[finding_idx]['ai_verified'] = True

        # Remover false positives das listas
        for category in security_categories:
            raw_findings[category] = [
                f for f in raw_findings.get(category, [])
                if f.get('severity') != 'false_positive'
            ]

        logger.info(f"AI classification done — {false_positive_count} false positives removed")
        raw_findings['ai_classified'] = True
        raw_findings['ai_model'] = self.model

        return raw_findings

    def _classify_batch(self, batch: List[Dict], start_idx: int) -> List[Dict]:
        """Classifica um batch de findings via Groq API"""
        client = self._get_client()
        if client is None:
            return [{'severity': f.get('raw_severity', f.get('severity', 'info')), 'reason': ''} for f in batch]

        # Montar texto dos findings
        findings_lines = []
        for i, finding in enumerate(batch):
            context = finding.get('context', finding.get('line_content', ''))
            # Limitar contexto para economizar tokens
            if len(context) > 300:
                context = context[:300] + '...'
            findings_lines.append(
                f"[{i}] type=\"{finding.get('type', '?')}\", "
                f"match=\"{finding.get('match', '')[:100]}\", "
                f"line={finding.get('line', 0)}, "
                f"raw_severity=\"{finding.get('raw_severity', finding.get('severity', 'info'))}\", "
                f"context=\"{context}\""
            )

        findings_text = '\n'.join(findings_lines)
        prompt = CLASSIFICATION_PROMPT.format(findings_text=findings_text)

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security analysis AI. Respond only with valid JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=2000,
                timeout=self.timeout,
            )

            content = response.choices[0].message.content.strip()
            return self._parse_response(content, batch)

        except Exception as e:
            logger.error(f"Groq API error: {e}")
            # Fallback: usar raw_severity
            return [{'severity': f.get('raw_severity', f.get('severity', 'info')), 'reason': ''} for f in batch]

    def _parse_response(self, content: str, batch: List[Dict]) -> List[Dict]:
        """Parsea resposta JSON da IA com fallback robusto"""
        # Tentar extrair JSON do conteudo
        try:
            # Remover markdown code blocks se existir
            clean = content
            if '```' in clean:
                match = re.search(r'```(?:json)?\s*([\s\S]*?)```', clean)
                if match:
                    clean = match.group(1)

            results = json.loads(clean)

            if isinstance(results, list):
                # Garantir que temos resultado pra cada finding
                while len(results) < len(batch):
                    idx = len(results)
                    results.append({
                        'severity': batch[idx].get('raw_severity', batch[idx].get('severity', 'info')),
                        'reason': '',
                    })

                # Validar severidades
                valid_severities = {'critical', 'high', 'medium', 'low', 'info', 'false_positive'}
                for r in results:
                    if r.get('severity', '').lower() not in valid_severities:
                        r['severity'] = 'info'
                    else:
                        r['severity'] = r['severity'].lower()

                return results

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse AI response: {e}")

        # Fallback total
        return [{'severity': f.get('raw_severity', f.get('severity', 'info')), 'reason': ''} for f in batch]
