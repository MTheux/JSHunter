"""
JSHunter — Entropy Analysis
Deteccao de segredos via calculo de entropia Shannon
"""

import re
import math
from typing import List, Dict, Any

from jshunter.engine.patterns import ENTROPY_EXCLUSIONS


def calculate_shannon_entropy(data: str) -> float:
    """Calcula a entropia Shannon de uma string"""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def find_high_entropy_strings(content: str, threshold: float = 4.5) -> List[Dict[str, Any]]:
    """
    Encontra strings de alta entropia no codigo fonte.
    Strings com alta entropia podem ser segredos, chaves ou tokens.
    """
    findings = []
    string_pattern = r'["\']([a-zA-Z0-9_\-\/\+\=]{20,})["\']'
    matches = re.finditer(string_pattern, content)
    seen = set()

    for match in matches:
        potential_secret = match.group(1)
        if potential_secret in seen:
            continue

        # Excluir strings comuns (URLs, MIME types, etc)
        if any(x in potential_secret.lower() for x in ENTROPY_EXCLUSIONS):
            continue

        entropy = calculate_shannon_entropy(potential_secret)
        if entropy > threshold:
            seen.add(potential_secret)
            line_num = content[:match.start()].count('\n') + 1
            lines = content.split('\n')
            findings.append({
                'type': 'High Entropy String',
                'match': potential_secret[:50] + '...' if len(potential_secret) > 50 else potential_secret,
                'entropy': round(entropy, 2),
                'line': line_num,
                'line_content': lines[line_num - 1].strip()[:100] if line_num <= len(lines) else '',
                'severity': 'high',
            })

    return findings
