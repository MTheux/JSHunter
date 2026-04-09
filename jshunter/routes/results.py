"""
JSHunter — Results Routes
Endpoints para consultar resultados de sessoes anteriores
"""

from flask import Blueprint, jsonify

results_bp = Blueprint('results', __name__)

# Referencia ao storage — sera injetado pelo app factory
_storage = None


def init_storage(storage: dict):
    """Injeta referencia ao storage de resultados"""
    global _storage
    _storage = storage


@results_bp.route('/api/results/<session_id>', methods=['GET'])
def get_results(session_id):
    """Retorna todos os resultados de uma sessao"""
    if _storage is None or session_id not in _storage:
        return jsonify({'error': 'Sessao nao encontrada'}), 404
    return jsonify(_storage[session_id])


@results_bp.route('/api/file/<session_id>/<int:file_id>', methods=['GET'])
def get_file_result(session_id, file_id):
    """Retorna resultado de um arquivo especifico"""
    if _storage is None or session_id not in _storage:
        return jsonify({'error': 'Sessao nao encontrada'}), 404

    files = _storage[session_id].get('files', [])
    file_result = next((f for f in files if f.get('file_id') == file_id), None)

    if not file_result:
        return jsonify({'error': 'Arquivo nao encontrado'}), 404
    return jsonify(file_result)
