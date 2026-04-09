"""
JSHunter — Pattern Database
Todos os padroes regex organizados por categoria
"""

# ========================================
# API KEY PATTERNS
# (regex, label, severity)
# ========================================
API_KEY_PATTERNS = [
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
CREDENTIAL_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Hardcoded Password', 'critical'),
    (r'(?i)(username|user[_-]?name|login)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Hardcoded Username', 'high'),
    (r'(?i)(db[_-]?password|database[_-]?password|db[_-]?pass)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Database Password', 'critical'),
    (r'(?i)(admin[_-]?password|root[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Admin Password', 'critical'),
    (r'(?i)(smtp[_-]?password|mail[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'Mail Password', 'critical'),
    (r'(?i)(ftp[_-]?password)\s*[:=]\s*["\']([^"\']{3,})["\']', 'FTP Password', 'critical'),
]

# ========================================
# EMAIL PATTERNS
# ========================================
EMAIL_PATTERNS = [
    (r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', 'Email Address', 'info'),
]

# ========================================
# COMMENT PATTERNS
# ========================================
COMMENT_PATTERNS = [
    (r'//\s*(TODO|FIXME|XXX|HACK|BUG|SECURITY|WARNING|DEPRECATED)', 'Interesting Comment', 'info'),
    (r'//\s*(password|secret|key|token|admin|backdoor|debug|test|vulnerability|exploit)', 'Suspicious Comment', 'medium'),
    (r'/\*[\s\S]*?(TODO|FIXME|XXX|HACK|BUG|SECURITY|WARNING|DEPRECATED)[\s\S]*?\*/', 'Multi-line Comment', 'info'),
]

# ========================================
# XSS / INJECTION PATTERNS (Fallback)
# ========================================
XSS_PATTERNS_FALLBACK = [
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
# PROTOTYPE POLLUTION
# ========================================
PROTOTYPE_POLLUTION_PATTERNS = [
    (r'__proto__\s*[\[.]', 'Prototype Pollution (__proto__)', 'high'),
    (r'constructor\s*\[\s*["\']prototype["\']', 'Prototype Pollution (constructor.prototype)', 'high'),
    (r'Object\.assign\s*\(\s*\{\}', 'Potential Prototype Pollution (Object.assign)', 'medium'),
]

# ========================================
# SSRF / OPEN REDIRECT
# ========================================
SSRF_REDIRECT_PATTERNS = [
    (r'(?i)(redirect|return[_-]?url|next|continue|dest|destination|redir|redirect_uri|return_to)\s*[:=]\s*["\']([^"\']+)["\']', 'Open Redirect Parameter', 'medium'),
    (r'window\.location\s*=\s*[^"\';\n]+', 'Dynamic Redirect', 'medium'),
    (r'window\.location\.replace\s*\([^"\']+\)', 'Dynamic Location Replace', 'medium'),
]

# ========================================
# SENSITIVE URLS / INTERNAL INFRA
# ========================================
SENSITIVE_URL_PATTERNS = [
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
API_ENDPOINT_PATTERNS = [
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

# ========================================
# PATH / DIRECTORY PATTERNS
# ========================================
PATH_PATTERNS = [
    (r'["\'](/[a-zA-Z0-9_\-/]+)["\']', 'Path'),
    (r'["\'](\.\.?/[a-zA-Z0-9_\-/]+)["\']', 'Relative Path'),
]

# ========================================
# PARAMETER PATTERNS
# ========================================
PARAMETER_PATTERNS = [
    (r'[?&](\w+)\s*=\s*([^&\s"\']+)', 'Query Parameter'),
]

# ========================================
# CREDENTIAL FALSE POSITIVE FILTERS
# Values that look like credentials but are labels/placeholders
# ========================================
CREDENTIAL_FALSE_POSITIVES = {
    # English labels/placeholders
    'password', 'your password', 'enter password', 'new password',
    'old password', 'confirm password', 'current password',
    'password here', 'type password', 'input password',
    'username', 'your username', 'enter username', 'user name',
    'email', 'your email', 'enter email', 'email address',
    'login', 'enter login', 'your login',
    # Portuguese labels
    'senha', 'sua senha', 'digite sua senha', 'nova senha',
    'confirmar senha', 'senha atual', 'confirme a senha',
    'usuario', 'nome de usuario', 'digite o usuario',
    # Common placeholder patterns
    'required', 'optional', 'placeholder', 'label',
    'text', 'string', 'value', 'input', 'field',
    'type', 'name', 'description', 'title',
    # Form field names / i18n keys
    'fullname', 'full name', 'first name', 'last name',
    'confirm_password', 'confirm password', 'new_password',
    'old_password', 'current_password', 'retype password',
}

# Patterns that indicate the value is a label/key, not a real secret
CREDENTIAL_LABEL_PATTERNS = [
    r'^[A-Z][a-z]+ [A-Z][a-z]+$',        # "Confirm Password" (Title Case label)
    r'^[A-Z_]+$',                          # "PASSWORD" (all caps constant name)
    r'^[a-z]+[A-Z][a-z]+',                 # "confirmPassword" (camelCase)
    r'^\*+$',                              # "****" (masked)
    r'^\.{3,}$',                           # "..." (placeholder dots)
    r'^x{3,}$',                            # "xxx" (placeholder)
]

# ========================================
# ENTROPY EXCLUSIONS
# ========================================
ENTROPY_EXCLUSIONS = [
    'application/', 'text/', 'http', 'www', 'function', 'return',
    'error', 'undefined', 'null', 'true', 'false', 'image/',
    'charset', 'content', 'accept', 'multipart',
]
