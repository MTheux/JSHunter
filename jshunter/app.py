"""
JSHunter — Flask App Factory
Cria e configura a aplicacao Flask
"""

import sys
import os
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

from jshunter.config import get_config
from jshunter.services.analyzer_service import AnalyzerService
from jshunter.routes.analysis import analysis_bp, init_analysis
from jshunter.routes.results import results_bp, init_storage
from jshunter.routes.health import health_bp
from jshunter.routes.spider import spider_bp, init_spider
from jshunter.utils.logger import logger


def create_app(env=None):
    """
    Factory function — cria e configura a aplicacao Flask.
    """
    config = get_config(env)

    # Aumentar recursion limit para AST de arquivos grandes
    sys.setrecursionlimit(getattr(config, 'RECURSION_LIMIT', 3000))

    # Descobrir diretorio base (raiz do projeto, nao o pacote)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, 'templates'),
        static_folder=os.path.join(base_dir, 'static'),
    )

    app.config['SECRET_KEY'] = config.SECRET_KEY
    CORS(app, origins=config.CORS_ORIGINS)

    # ---- Storage (in-memory, trocar por Redis/DB em prod) ----
    analysis_storage = {}

    # ---- Services ----
    service = AnalyzerService(config)

    # ---- Inject dependencies into blueprints ----
    init_analysis(analysis_storage, service)
    init_storage(analysis_storage)
    init_spider(analysis_storage, service)

    # ---- Register blueprints ----
    app.register_blueprint(analysis_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(spider_bp)

    # ---- Root route ----
    @app.route('/')
    def index():
        from flask import render_template
        return render_template('index.html')

    # ---- Serve local JS files for testing ----
    @app.route('/<path:filename>')
    def serve_file(filename):
        if filename.startswith(('api/', 'static/', 'templates/')):
            return jsonify({'error': 'Not found'}), 404
        if filename.endswith('.js'):
            try:
                return send_from_directory(base_dir, filename, mimetype='application/javascript')
            except FileNotFoundError:
                return jsonify({'error': f'Arquivo {filename} nao encontrado'}), 404
        return jsonify({'error': 'Arquivo nao encontrado'}), 404

    logger.info(f"JSHunter v{config.APP_VERSION} initialized ({env or 'development'})")
    return app
