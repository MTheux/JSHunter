#!/usr/bin/env python3
"""
JSHunter — Launcher
Desenvolvido por HuntBox — Empresa 100% ofensiva
Pentest | Red Team | Bug Bounty

Usage:
  python app.py              # Development (debug=True, port 5000)
  JSHUNTER_ENV=production python app.py  # Production
"""

import os
from jshunter.app import create_app
from jshunter.config import get_config

env = os.environ.get("JSHUNTER_ENV", "development")
config = get_config(env)
app = create_app(env)

if __name__ == '__main__':
    app.run(
        debug=config.DEBUG,
        host=config.HOST,
        port=config.PORT,
    )
