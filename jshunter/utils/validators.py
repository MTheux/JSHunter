"""
JSHunter — Validators
Validacao de input: URLs, arquivos, limites
"""

from urllib.parse import urlparse
from typing import List, Tuple, Optional


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Valida uma URL de target.
    Retorna (valido, erro_ou_none)
    """
    if not url or not url.strip():
        return False, "URL vazia"

    url = url.strip()

    # Substituir 0.0.0.0 por localhost
    if '0.0.0.0' in url:
        url = url.replace('0.0.0.0', 'localhost')

    try:
        parsed = urlparse(url)
    except Exception:
        return False, f"URL malformada: {url[:100]}"

    if parsed.scheme not in ('http', 'https'):
        return False, f"Protocolo invalido: {parsed.scheme}. Use http ou https"

    if not parsed.netloc:
        return False, "URL sem dominio"

    return True, None


def sanitize_url(url: str) -> str:
    """Sanitiza uma URL removendo whitespace e corrigindo 0.0.0.0"""
    url = url.strip()
    if '0.0.0.0' in url:
        url = url.replace('0.0.0.0', 'localhost')
    return url


def validate_urls(urls: List[str]) -> Tuple[List[str], List[str]]:
    """
    Valida uma lista de URLs.
    Retorna (urls_validas, erros)
    """
    valid = []
    errors = []

    for url in urls:
        url = url.strip()
        if not url or url.startswith('#'):
            continue

        is_valid, error = validate_url(url)
        if is_valid:
            valid.append(sanitize_url(url))
        else:
            errors.append(error)

    return valid, errors


ALLOWED_EXTENSIONS = {'.js', '.json', '.html', '.htm', '.txt', '.csv'}


def validate_file_upload(filename: str, content_length: int = 0,
                         max_size: int = 20 * 1024 * 1024) -> Tuple[bool, Optional[str]]:
    """
    Valida um arquivo de upload.
    Retorna (valido, erro_ou_none)
    """
    if not filename:
        return False, "Nenhum arquivo selecionado"

    ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extensao nao suportada: {ext}. Use: {', '.join(ALLOWED_EXTENSIONS)}"

    if content_length > max_size:
        size_mb = max_size / (1024 * 1024)
        return False, f"Arquivo muito grande. Maximo: {size_mb:.0f}MB"

    return True, None
