#!/usr/bin/env python3
"""
JSHunter — Advanced JavaScript Security Analyzer
Motor Híbrido: AST (Contextual) + Regex (Padrões)
Desenvolvido por HuntBox — Empresa 100% ofensiva
Pentest • Red Team • Bug Bounty
"""

import re
import math
import requests
import jsbeautifier
import esprima
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnalysisResult:
    """Structure for analysis results"""
    url: str
    api_keys: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    interesting_comments: List[Dict[str, Any]]
    xss_vulnerabilities: List[Dict[str, Any]]
    xss_functions: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    paths_directories: List[Dict[str, Any]]
    high_entropy_strings: List[Dict[str, Any]]
    source_map_detected: bool
    source_map_url: str
    errors: List[str]
    file_size: int
    analysis_timestamp: str
    analysis_engine: str
    risk_score: int  # 0-100 risk score
    severity_counts: Dict[str, int]  # critical, high, medium, low, info


class ASTVisitor:
    """Classe auxiliar para navegar na árvore sintática do JavaScript"""
    def __init__(self):
        self.findings = {
            'credentials': [],
            'xss': [],
            'frameworks': set(),
            'dangerous_functions': [],
        }
        self.sensitive_vars = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'auth',
            'api_key', 'access_token', 'refresh_token', 'private_key',
            'client_secret', 'session_token', 'bearer', 'authorization',
        }
        self.sinks = {'eval', 'setTimeout', 'setInterval', 'execScript', 'Function'}
        self.dom_sinks = {'innerHTML', 'outerHTML', 'document.write', 'document.writeln'}

    def visit(self, node):
        """Visita recursiva aos nós"""
        method_name = 'visit_' + node.type
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        """Navega pelos filhos do nó atual"""
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.visit(item)
            elif hasattr(value, 'type'):
                self.visit(value)

    def visit_VariableDeclarator(self, node):
        """Analisa declarações: const password = "123";"""
        if node.id.type == 'Identifier' and node.init:
            var_name = node.id.name.lower()
            if any(s in var_name for s in self.sensitive_vars):
                if node.init.type == 'Literal' and isinstance(node.init.value, str):
                    if len(node.init.value) > 3:
                        self.findings['credentials'].append({
                            'type': 'Hardcoded Credential (AST)',
                            'match': f'{node.id.name} = "{node.init.value[:20]}..."',
                            'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                            'severity': 'critical',
                            'confidence': 'High'
                        })
        self.generic_visit(node)

    def visit_AssignmentExpression(self, node):
        """Analisa atribuições: element.innerHTML = userInput;"""
        if node.left.type == 'MemberExpression' and node.left.property.type == 'Identifier':
            prop_name = node.left.property.name
            if prop_name in self.dom_sinks:
                is_safe = (node.right.type == 'Literal')
                if not is_safe:
                    self.findings['xss'].append({
                        'type': f'DOM XSS Sink ({prop_name})',
                        'match': f'Assignment to {prop_name} with dynamic content',
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'severity': 'high'
                    })

            # Detect postMessage usage
            if prop_name == 'onmessage':
                self.findings['xss'].append({
                    'type': 'postMessage Handler',
                    'match': 'onmessage handler detected — verify origin validation',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                    'severity': 'medium'
                })

        self.generic_visit(node)

    def visit_CallExpression(self, node):
        """Analisa chamadas de função: eval(code), React.createElement(...)"""
        # 1. Sinks de Execução (eval, Function, etc)
        if node.callee.type == 'Identifier':
            func_name = node.callee.name
            if func_name in self.sinks:
                if node.arguments and node.arguments[0].type != 'Literal':
                    self.findings['xss'].append({
                        'type': f'Execution Sink ({func_name})',
                        'match': f'Call to {func_name} with dynamic argument',
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'severity': 'critical'
                    })

            # postMessage detection
            if func_name == 'postMessage':
                self.findings['xss'].append({
                    'type': 'postMessage Usage',
                    'match': 'postMessage() called — check for origin validation',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                    'severity': 'medium'
                })

            # Framework detection
            if 'vue' in func_name.lower(): self.findings['frameworks'].add('Vue.js')
            if 'angular' in func_name.lower(): self.findings['frameworks'].add('Angular')

        # 2. MemberExpression calls
        if node.callee.type == 'MemberExpression':
            if hasattr(node.callee.object, 'name') and node.callee.object.name == 'React':
                self.findings['frameworks'].add('React')

            # Detect window.open with dynamic URL
            if (hasattr(node.callee.object, 'name') and
                node.callee.object.name == 'window' and
                hasattr(node.callee.property, 'name') and
                node.callee.property.name == 'open'):
                if node.arguments and node.arguments[0].type != 'Literal':
                    self.findings['xss'].append({
                        'type': 'Open Redirect Risk',
                        'match': 'window.open() with dynamic URL',
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'severity': 'medium'
                    })

            # Detect document.cookie access
            if (hasattr(node.callee.object, 'type') and
                node.callee.object.type == 'MemberExpression'):
                try:
                    obj = node.callee.object
                    if (hasattr(obj.object, 'name') and obj.object.name == 'document' and
                        hasattr(obj.property, 'name') and obj.property.name == 'cookie'):
                        self.findings['dangerous_functions'].append({
                            'type': 'Cookie Manipulation',
                            'match': 'document.cookie access detected',
                            'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                            'severity': 'medium'
                        })
                except AttributeError:
                    pass

        self.generic_visit(node)

    def visit_Property(self, node):
        """Analisa propriedades de objetos"""
        if node.key.type == 'Identifier' and node.key.name == 'dangerouslySetInnerHTML':
            self.findings['xss'].append({
                'type': 'React Dangerous Sink',
                'match': 'dangerouslySetInnerHTML usage detected',
                'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                'severity': 'high'
            })
            self.findings['frameworks'].add('React')
        self.generic_visit(node)

    def visit_NewExpression(self, node):
        """Detect new Function() constructor"""
        if node.callee.type == 'Identifier' and node.callee.name == 'Function':
            if node.arguments:
                self.findings['xss'].append({
                    'type': 'Dynamic Function Constructor',
                    'match': 'new Function() with dynamic code — equivalent to eval()',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                    'severity': 'critical'
                })
        self.generic_visit(node)


class JavaScriptAnalyzer:
    """JSHunter — Analisador Híbrido: AST + Regex"""

    def __init__(self):
        self.beautifier_opts = jsbeautifier.default_options()
        self.beautifier_opts.indent_size = 2

        # ========================================
        # API KEY PATTERNS (50+ patterns)
        # ========================================
        self.api_key_patterns = [
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical'),
            (r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS Secret Key', 'critical'),
            (r'(?i)aws[_-]?session[_-]?token\s*[:=]\s*["\']([a-zA-Z0-9/+=]{100,})["\']', 'AWS Session Token', 'critical'),

            # Google / GCP
            (r'AIza[0-9A-Za-z\-]{35}', 'Google API Key', 'critical'),
            (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Google API Key (Variable)', 'high'),
            (r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com', 'Google OAuth Client ID', 'high'),
            (r'ya29\.[0-9A-Za-z\-_]+', 'Google OAuth Access Token', 'critical'),

            # GitHub
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 'critical'),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained Token', 'critical'),
            (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token', 'critical'),
            (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Server Token', 'critical'),
            (r'ghu_[a-zA-Z0-9]{36}', 'GitHub User Token', 'critical'),

            # Stripe
            (r'sk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Secret Key', 'critical'),
            (r'sk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Secret Key', 'high'),
            (r'pk_live_[a-zA-Z0-9]{24,}', 'Stripe Live Publishable Key', 'medium'),
            (r'pk_test_[a-zA-Z0-9]{24,}', 'Stripe Test Publishable Key', 'low'),
            (r'rk_live_[a-zA-Z0-9]{24,}', 'Stripe Restricted Key', 'critical'),

            # PayPal
            (r'access_token\$production\$[a-zA-Z0-9]{22}\$[a-zA-Z0-9]{86}', 'PayPal Access Token', 'critical'),

            # Slack
            (r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 'Slack Token', 'critical'),
            (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}', 'Slack Webhook URL', 'high'),

            # Discord
            (r'(?i)discord[a-z0-9_ .\-,]{0,25}(token|key|secret|password|pass|pwd|authorization)\s*[:=]\s*["\']([a-zA-Z0-9_.]{24,})["\']', 'Discord Token', 'critical'),
            (r'https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+', 'Discord Webhook URL', 'high'),

            # Firebase
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging Token', 'critical'),

            # Twilio
            (r'SK[0-9a-fA-F]{32}', 'Twilio API Key', 'critical'),
            (r'AC[a-zA-Z0-9]{32}', 'Twilio Account SID', 'high'),

            # SendGrid
            (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', 'SendGrid API Key', 'critical'),

            # Mailgun
            (r'key-[a-zA-Z0-9]{32}', 'Mailgun API Key', 'critical'),

            # Heroku
            (r'(?i)heroku[a-z0-9_ .\-,]{0,25}(api[_-]?key|token|secret)\s*[:=]\s*["\']([a-zA-Z0-9\-]{36})["\']', 'Heroku API Key', 'critical'),

            # Azure
            (r'(?i)azure[a-z0-9_ .\-,]{0,25}(key|token|secret|password)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40,})["\']', 'Azure Secret', 'critical'),

            # DigitalOcean
            (r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Personal Access Token', 'critical'),
            (r'doo_v1_[a-f0-9]{64}', 'DigitalOcean OAuth Token', 'critical'),

            # Shopify
            (r'shppa_[a-fA-F0-9]{32}', 'Shopify Private App Password', 'critical'),
            (r'shpat_[a-fA-F0-9]{32}', 'Shopify Admin Token', 'critical'),

            # Square
            (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token', 'critical'),
            (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square OAuth Secret', 'critical'),

            # Telegram
            (r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}', 'Telegram Bot Token', 'critical'),

            # npm
            (r'npm_[a-zA-Z0-9]{36}', 'npm Access Token', 'critical'),

            # JWT
            (r'\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]{10,}\b', 'JWT Token', 'high'),

            # Private Keys
            (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key', 'critical'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'critical'),

            # Generic
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{32,})["\']', 'Generic API Key', 'high'),
            (r'(?i)(token|secret|auth[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'Generic Token', 'medium'),
            (r'(?i)(connection[_-]?string)\s*[:=]\s*["\']([^"\']{20,})["\']', 'Connection String', 'critical'),
        ]

        # ========================================
        # CREDENTIAL PATTERNS
        # ========================================
        self.credential_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Hardcoded Password', 'critical'),
            (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Hardcoded Username', 'high'),
            (r'(?i)(db[_-]?password|database[_-]?password|db[_-]?pass)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Database Password', 'critical'),
            (r'(?i)(admin[_-]?password|root[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Admin Password', 'critical'),
            (r'(?i)(smtp[_-]?password|mail[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Mail Password', 'critical'),
            (r'(?i)(ftp[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'FTP Password', 'critical'),
        ]

        self.email_patterns = [
            (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', 'info'),
        ]

        self.comment_patterns = [
            (r'//\s*(TODO|FIXME|XXX|HACK|BUG|SECURITY|WARNING|DEPRECATED)', 'Interesting Comment', 'info'),
            (r'//\s*(password|secret|key|token|admin|backdoor|debug|test|vulnerability|exploit)', 'Suspicious Comment', 'medium'),
            (r'/\*[\s\S]*?(TODO|FIXME|XXX|HACK|BUG|SECURITY|WARNING|DEPRECATED)[\s\S]*?\*/', 'Multi-line Comment', 'info'),
        ]

        # ========================================
        # XSS / INJECTION PATTERNS (Fallback)
        # ========================================
        self.xss_patterns_fallback = [
            (r'\.innerHTML\s*=\s*([^;]+)', 'innerHTML Assignment', 'high'),
            (r'\.outerHTML\s*=\s*([^;]+)', 'outerHTML Assignment', 'high'),
            (r'document\.write\s*\(([^)]+)\)', 'document.write()', 'high'),
            (r'document\.writeln\s*\(([^)]+)\)', 'document.writeln()', 'high'),
            (r'eval\s*\([^)]*(\$|location|window\.|document\.|user)', 'eval() with User Input', 'critical'),
            (r'dangerouslySetInnerHTML\s*=\s*\{', 'React dangerouslySetInnerHTML', 'high'),
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', 'jQuery .html()', 'medium'),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', 'jQuery .append()', 'medium'),
            (r'location\.(href|hash|search)\s*=\s*([^;]+)', 'Location Manipulation', 'medium'),
            (r'innerHTML\s*[+\=]\s*["\']', 'innerHTML Concatenation', 'high'),
            (r'new\s+Function\s*\(', 'Dynamic Function Constructor', 'critical'),
            (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML()', 'high'),
            (r'document\.createElement\s*\(\s*["\']script["\']', 'Dynamic Script Creation', 'high'),
            (r'\.setAttribute\s*\(\s*["\']on\w+["\']', 'Event Handler Injection', 'high'),
            (r'javascript\s*:', 'JavaScript Protocol', 'medium'),
        ]

        # ========================================
        # PROTOTYPE POLLUTION PATTERNS
        # ========================================
        self.prototype_pollution_patterns = [
            (r'__proto__\s*[\[.]', 'Prototype Pollution (__proto__)', 'high'),
            (r'constructor\s*\[\s*["\']prototype["\']', 'Prototype Pollution (constructor.prototype)', 'high'),
            (r'Object\.assign\s*\(\s*\{\}', 'Potential Prototype Pollution (Object.assign)', 'medium'),
        ]

        # ========================================
        # SSRF / OPEN REDIRECT PATTERNS
        # ========================================
        self.ssrf_redirect_patterns = [
            (r'(?i)(redirect|return[_-]?url|next|continue|dest|destination|redir|redirect_uri|return_to)\s*[:=]\s*["\']([^"\']+)["\']', 'Open Redirect Parameter', 'medium'),
            (r'window\.location\s*=\s*[^"\';\n]+', 'Dynamic Redirect', 'medium'),
            (r'window\.location\.replace\s*\([^"\']+\)', 'Dynamic Location Replace', 'medium'),
        ]

        # ========================================
        # SENSITIVE URL / INTERNAL INFRA
        # ========================================
        self.sensitive_url_patterns = [
            (r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]?[^\s"\']*', 'Internal/Private URL', 'high'),
            (r'(?i)(staging|internal|dev|test|sandbox|preprod|uat)\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', 'Internal/Staging Domain', 'medium'),
            (r'(?i)mongodb(\+srv)?://[^\s"\']+', 'MongoDB Connection String', 'critical'),
            (r'(?i)postgres(ql)?://[^\s"\']+', 'PostgreSQL Connection String', 'critical'),
            (r'(?i)mysql://[^\s"\']+', 'MySQL Connection String', 'critical'),
            (r'(?i)redis://[^\s"\']+', 'Redis Connection String', 'critical'),
            (r'(?i)amqp://[^\s"\']+', 'RabbitMQ Connection String', 'critical'),
            (r'(?i)s3://[a-zA-Z0-9\-]+', 'AWS S3 Bucket URL', 'high'),
        ]

        # ========================================
        # API ENDPOINT PATTERNS
        # ========================================
        self.api_patterns = [
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch()'),
            (r'fetch\s*\(\s*`([^`]+)`', 'fetch() (template)'),
            (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios (config)'),
            (r'\.open\s*\(\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', 'XMLHttpRequest'),
            (r'\$\.(ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX (short)'),
            (r'\$\.getJSON\s*\(\s*["\']([^"\']+)["\']', 'jQuery getJSON'),
            (r'["\'](/api/[^"\']+)["\']', 'API Path'),
            (r'["\'](/v\d+/[^"\']+)["\']', 'API Versioned Path'),
            (r'baseURL\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'(?i)api[_-]?url\s*[:=]\s*["\']([^"\']+)["\']', 'API URL Variable'),
            (r'["\'](https?://[^"\']+/api/[^"\']*)["\']', 'Full API URL'),
            (r'(?i)graphql\s*[:=]\s*["\']([^"\']+)["\']', 'GraphQL Endpoint'),
            (r'["\'](/graphql[^"\']*)["\']', 'GraphQL Path'),
            (r'(?i)websocket|wss?://[^\s"\']+', 'WebSocket Endpoint'),
        ]

        self.path_patterns = [
            (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
            (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
        ]

        self.parameter_patterns = [
            (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
        ]

    def calculate_shannon_entropy(self, data: str) -> float:
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_source_map(self, content: str, url: str) -> tuple:
        match = re.search(r'//# sourceMappingURL=([^\s]+)', content)
        if match:
            map_url = match.group(1)
            if not map_url.startswith('http') and 'http' in url:
                base_url = url.rsplit('/', 1)[0]
                map_url = f"{base_url}/{map_url}"
            return True, map_url
        return False, ""

    def find_high_entropy_strings(self, content: str, threshold=4.5) -> List[Dict[str, Any]]:
        findings = []
        string_pattern = r'["\']([a-zA-Z0-9_\-\/\+\=]{20,})["\']'
        matches = re.finditer(string_pattern, content)
        seen = set()

        for match in matches:
            potential_secret = match.group(1)
            if potential_secret in seen:
                continue
            if any(x in potential_secret.lower() for x in [
                'application/', 'text/', 'http', 'www', 'function', 'return',
                'error', 'undefined', 'null', 'true', 'false', 'image/',
                'charset', 'content', 'accept', 'multipart',
            ]):
                continue

            entropy = self.calculate_shannon_entropy(potential_secret)
            if entropy > threshold:
                seen.add(potential_secret)
                line_num = content[:match.start()].count('\n') + 1
                findings.append({
                    'type': 'High Entropy String',
                    'match': potential_secret[:50] + '...' if len(potential_secret) > 50 else potential_secret,
                    'entropy': round(entropy, 2),
                    'line': line_num,
                    'line_content': content.split('\n')[line_num - 1].strip()[:100],
                    'severity': 'high'
                })
        return findings

    def fetch_js_file(self, url: str) -> Optional[str]:
        try:
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
            }
            response = requests.get(url, headers=headers, timeout=60, verify=False, allow_redirects=True)
            if response.status_code == 200:
                return response.text
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def find_patterns(self, content: str, patterns: List[tuple], context_lines: int = 2) -> List[Dict[str, Any]]:
        """Método de Regex para padrões"""
        findings = []
        lines = content.split('\n')
        seen = set()

        for pattern_info in patterns:
            pattern = pattern_info[0]
            label = pattern_info[1]
            severity = pattern_info[2] if len(pattern_info) > 2 else 'info'

            try:
                for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    match_text = match.group(0)[:150]

                    # Dedup by label+line
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
                        'severity': severity
                    })
            except Exception:
                continue
        return findings

    def analyze_ast(self, content: str) -> Optional[Dict[str, List]]:
        """Executa a análise AST usando Esprima"""
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

    def calculate_risk_score(self, findings_counts: Dict[str, int]) -> int:
        """Calculate a 0-100 risk score based on findings"""
        score = 0
        score += findings_counts.get('critical', 0) * 25
        score += findings_counts.get('high', 0) * 15
        score += findings_counts.get('medium', 0) * 8
        score += findings_counts.get('low', 0) * 3
        score += findings_counts.get('info', 0) * 1
        return min(score, 100)

    def count_severities(self, all_findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = str(f.get('severity', 'info')).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def analyze(self, url: str, content: str = None) -> AnalysisResult:
        errors = []
        if content is None:
            content = self.fetch_js_file(url)
            if content is None:
                return self._empty_result(url, ["Failed to fetch URL"])

        file_size = len(content)
        has_source_map, source_map_url = self.detect_source_map(content, url)

        # Beautify if minified
        if len(content.split('\n')) < 5 and len(content) > 1000:
            try:
                content = jsbeautifier.beautify(content, self.beautifier_opts)
            except Exception:
                pass

        # --- PHASE 1: AST ANALYSIS ---
        ast_findings = self.analyze_ast(content)
        used_engine = 'AST + Regex' if ast_findings else 'Regex Only'

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
                        'severity': 'info'
                    })

        # --- PHASE 2: REGEX ANALYSIS ---
        api_keys = self.find_patterns(content, self.api_key_patterns)
        credentials.extend(self.find_patterns(content, self.credential_patterns))
        emails = self.find_patterns(content, self.email_patterns)
        comments = self.find_patterns(content, self.comment_patterns)
        high_entropy = self.find_high_entropy_strings(content)

        # XSS fallback
        if not ast_findings or (not xss_vulns and not credentials):
            xss_vulns.extend(self.find_patterns(content, self.xss_patterns_fallback))

        # Prototype pollution
        xss_vulns.extend(self.find_patterns(content, self.prototype_pollution_patterns))

        # SSRF / Open Redirect
        xss_vulns.extend(self.find_patterns(content, self.ssrf_redirect_patterns))

        # Sensitive URLs
        api_keys.extend(self.find_patterns(content, self.sensitive_url_patterns))

        # Endpoints
        api_endpoints = self.find_patterns(content, self.api_patterns)
        parameters = self.find_patterns(content, self.parameter_patterns)
        paths = self.find_patterns(content, self.path_patterns)

        # --- RISK SCORE ---
        all_findings = api_keys + credentials + xss_vulns + high_entropy
        severity_counts = self.count_severities(all_findings)
        risk_score = self.calculate_risk_score(severity_counts)

        return AnalysisResult(
            url=url,
            api_keys=api_keys,
            credentials=credentials,
            emails=emails,
            interesting_comments=comments,
            xss_vulnerabilities=xss_vulns,
            xss_functions=[],
            api_endpoints=api_endpoints,
            parameters=parameters,
            paths_directories=paths,
            high_entropy_strings=high_entropy,
            source_map_detected=has_source_map,
            source_map_url=source_map_url,
            errors=errors,
            file_size=file_size,
            analysis_timestamp=datetime.now().isoformat(),
            analysis_engine=used_engine,
            risk_score=risk_score,
            severity_counts=severity_counts,
        )

    def _empty_result(self, url, errors):
        return AnalysisResult(
            url=url, api_keys=[], credentials=[], emails=[], interesting_comments=[],
            xss_vulnerabilities=[], xss_functions=[], api_endpoints=[], parameters=[],
            paths_directories=[], high_entropy_strings=[], source_map_detected=False,
            source_map_url="", errors=errors, file_size=0,
            analysis_timestamp=datetime.now().isoformat(), analysis_engine="None",
            risk_score=0, severity_counts={'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        )
