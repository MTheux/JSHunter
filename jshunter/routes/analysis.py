"""
JSHunter — Analysis Routes
Endpoint principal de analise de JavaScript
"""

import json
import uuid
from flask import Blueprint, request, jsonify

from jshunter.services.analyzer_service import AnalyzerService
from jshunter.utils.validators import validate_url, validate_file_upload, sanitize_url
from jshunter.utils.logger import logger

analysis_bp = Blueprint('analysis', __name__)

# Referencia ao storage e service — injetados pelo app factory
_storage = None
_service = None


def init_analysis(storage: dict, service: AnalyzerService):
    """Injeta dependencias"""
    global _storage, _service
    _storage = storage
    _service = service


@analysis_bp.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Endpoint principal de analise.
    Suporta: URL unica, multiplas URLs, upload de arquivo.
    """
    try:
        urls = []
        is_direct_upload = False
        direct_filename = ""
        direct_content = ""

        if request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'JSON invalido'}), 400

            urls = data.get('urls', [])
            if isinstance(urls, str):
                urls = [urls]
            if not urls:
                url = data.get('url', '').strip()
                if url:
                    urls = [url]
            if not urls:
                return jsonify({'error': 'URL(s) sao obrigatorias'}), 400

            # Validar URLs
            validated = []
            for u in urls:
                u = sanitize_url(u)
                is_valid, error = validate_url(u)
                if is_valid:
                    validated.append(u)
                else:
                    logger.warning(f"URL invalida ignorada: {error}")
            urls = validated

            if not urls:
                return jsonify({'error': 'Nenhuma URL valida fornecida'}), 400

        else:
            # File upload
            if 'file' not in request.files:
                return jsonify({'error': 'Nenhum arquivo ou dados fornecidos'}), 400

            file = request.files['file']
            if not file.filename:
                return jsonify({'error': 'Nenhum arquivo enviado'}), 400

            is_valid, error = validate_file_upload(file.filename)
            if not is_valid:
                return jsonify({'error': error}), 400

            filename_lower = file.filename.lower()
            content = file.read().decode('utf-8', errors='ignore')

            if any(filename_lower.endswith(ext) for ext in ['.js', '.html', '.htm', '.txt']):
                lines = content.split('\n')
                valid_urls = [l.strip() for l in lines[:5]
                              if l.strip().startswith(('http://', 'https://'))]

                if len(valid_urls) > 0 and len(lines) < 1000:
                    urls = [line.strip() for line in lines
                            if line.strip() and not line.strip().startswith('#')]
                else:
                    is_direct_upload = True
                    direct_filename = file.filename
                    direct_content = content

            elif filename_lower.endswith('.json'):
                try:
                    json_data = json.loads(content)
                    if isinstance(json_data, list):
                        urls = [str(u).strip() for u in json_data]
                    elif isinstance(json_data, dict) and 'urls' in json_data:
                        urls = [str(u).strip() for u in json_data['urls']]
                except json.JSONDecodeError:
                    is_direct_upload = True
                    direct_filename = file.filename
                    direct_content = content

            elif filename_lower.endswith('.csv'):
                urls = [line.strip() for line in content.split('\n')
                        if line.strip() and not line.strip().startswith('#')]
            else:
                is_direct_upload = True
                direct_filename = file.filename
                direct_content = content

        # Gerar sessao
        session_id = str(uuid.uuid4())
        total_files = 1 if is_direct_upload else len(urls)

        _storage[session_id] = {
            'files': [],
            'total': total_files,
            'completed': 0,
        }

        results = []

        def format_result(file_id, res_obj):
            d = res_obj.to_dict()
            d['file_id'] = file_id
            return d

        if is_direct_upload:
            try:
                result = _service.analyze_content(
                    f"Upload: {direct_filename}", direct_content
                )
                result_dict = format_result(1, result)
                results.append(result_dict)
                _storage[session_id]['files'].append(result_dict)
                _storage[session_id]['completed'] = 1
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                return jsonify({'error': f'Falha na analise: {str(e)}'}), 500
        else:
            for idx, url in enumerate(urls):
                url = url.strip()
                if not url:
                    continue
                try:
                    result = _service.analyze_url(url)
                    result_dict = format_result(idx + 1, result)
                    results.append(result_dict)
                    _storage[session_id]['files'].append(result_dict)
                    _storage[session_id]['completed'] += 1
                except Exception as e:
                    logger.error(f"Analysis failed for {url}: {e}")
                    error_result = {
                        'file_id': idx + 1,
                        'url': url,
                        'errors': [f'Falha critica: {str(e)}'],
                        'api_keys': [], 'credentials': [], 'emails': [],
                        'interesting_comments': [], 'xss_vulnerabilities': [],
                        'xss_functions': [], 'api_endpoints': [], 'parameters': [],
                        'paths_directories': [], 'high_entropy_strings': [],
                        'source_map_detected': False, 'source_map_url': '',
                        'analysis_engine': 'Failed', 'risk_score': 0,
                        'severity_counts': {},
                        'file_size': 0, 'analysis_timestamp': '',
                    }
                    results.append(error_result)
                    _storage[session_id]['files'].append(error_result)
                    _storage[session_id]['completed'] += 1

        return jsonify({
            'session_id': session_id,
            'total_files': len(results),
            'results': results,
        })

    except Exception as e:
        logger.error(f"Unhandled error in /api/analyze: {e}")
        return jsonify({'error': str(e)}), 500
