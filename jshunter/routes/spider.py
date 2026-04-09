"""
JSHunter — Spider Routes
Endpoint para crawl automatico de JS via browser headless
"""

import uuid
from flask import Blueprint, request, jsonify

from jshunter.engine.spider import SpiderEngine
from jshunter.services.analyzer_service import AnalyzerService
from jshunter.utils.validators import validate_url, sanitize_url
from jshunter.utils.logger import logger

spider_bp = Blueprint('spider', __name__)

_storage = None
_service = None


def init_spider(storage: dict, service: AnalyzerService):
    """Injeta dependencias"""
    global _storage, _service
    _storage = storage
    _service = service


@spider_bp.route('/api/spider', methods=['POST'])
def spider():
    """
    Spider Mode — Recebe URL de um site, descobre todos os JS,
    analisa cada um com os 3 motores.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON invalido'}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'URL e obrigatoria'}), 400

        url = sanitize_url(url)
        is_valid, error = validate_url(url)
        if not is_valid:
            return jsonify({'error': f'URL invalida: {error}'}), 400

        logger.info(f"Spider request: {url}")

        # --- Fase 1: Crawl ---
        spider_engine = SpiderEngine(
            max_pages=int(data.get('max_pages', 15)),
            timeout=int(data.get('timeout', 15000)),
        )
        crawl_result = spider_engine.crawl(url)

        if not crawl_result.scripts and crawl_result.errors:
            return jsonify({
                'error': 'Spider falhou: ' + '; '.join(crawl_result.errors),
                'pages_crawled': crawl_result.pages_crawled,
            }), 500

        # --- Fase 2: Analise de cada JS ---
        session_id = str(uuid.uuid4())
        results = []

        _storage[session_id] = {
            'files': [],
            'total': len(crawl_result.scripts),
            'completed': 0,
        }

        for idx, script in enumerate(crawl_result.scripts):
            try:
                result = _service.analyze_content(script.url, script.content)
                result_dict = result.to_dict()
                result_dict['file_id'] = idx + 1
                result_dict['source_page'] = script.source_page
                result_dict['file_size'] = script.size
                results.append(result_dict)
                _storage[session_id]['files'].append(result_dict)
                _storage[session_id]['completed'] += 1
            except Exception as e:
                logger.error(f"Spider analysis failed for {script.url}: {e}")
                error_result = {
                    'file_id': idx + 1,
                    'url': script.url,
                    'source_page': script.source_page,
                    'errors': [f'Analise falhou: {str(e)[:200]}'],
                    'api_keys': [], 'credentials': [], 'emails': [],
                    'interesting_comments': [], 'xss_vulnerabilities': [],
                    'xss_functions': [], 'api_endpoints': [], 'parameters': [],
                    'paths_directories': [], 'high_entropy_strings': [],
                    'source_map_detected': False, 'source_map_url': '',
                    'analysis_engine': 'Failed', 'risk_score': 0,
                    'severity_counts': {},
                    'file_size': script.size,
                    'analysis_timestamp': '',
                }
                results.append(error_result)
                _storage[session_id]['files'].append(error_result)
                _storage[session_id]['completed'] += 1

        return jsonify({
            'session_id': session_id,
            'target_url': url,
            'pages_crawled': crawl_result.pages_crawled,
            'scripts_found': crawl_result.scripts_found,
            'scripts_ignored': crawl_result.scripts_ignored,
            'total_files': len(results),
            'results': results,
        })

    except Exception as e:
        logger.error(f"Spider error: {e}")
        return jsonify({'error': str(e)}), 500
