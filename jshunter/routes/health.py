"""
JSHunter — Health Route
Endpoint de status do servidor
"""

from flask import Blueprint, jsonify
from jshunter import __version__

health_bp = Blueprint('health', __name__)


@health_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'operational',
        'tool': 'JSHunter',
        'version': __version__,
        'author': 'HuntBox',
        'engine': 'AST + Regex Hybrid',
    })
