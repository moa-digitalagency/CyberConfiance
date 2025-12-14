SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key exposée', 'critical'),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'Secret Key exposée', 'critical'),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', 'Mot de passe hardcodé', 'critical'),
    (r'(?i)(token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'Token exposé', 'critical'),
    (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?', 'AWS Access Key exposée', 'critical'),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key exposée', 'critical'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID détectée', 'critical'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token exposé', 'critical'),
    (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained PAT exposé', 'critical'),
    (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token exposé', 'critical'),
    (r'ghr_[a-zA-Z0-9]{36}', 'GitHub Refresh Token exposé', 'critical'),
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key exposée', 'critical'),
    (r'sk-proj-[a-zA-Z0-9\-_]{80,}', 'OpenAI Project API Key exposée', 'critical'),
    (r'sk-ant-[a-zA-Z0-9\-_]{80,}', 'Anthropic API Key exposée', 'critical'),
    (r'xox[baprs]-[a-zA-Z0-9\-]{10,}', 'Slack Token exposé', 'critical'),
    (r'(?i)(mongodb(\+srv)?://[^"\'\s]+)', 'MongoDB Connection String exposée', 'critical'),
    (r'(?i)(postgres(ql)?://[^"\'\s]+)', 'PostgreSQL Connection String exposée', 'critical'),
    (r'(?i)(mysql://[^"\'\s]+)', 'MySQL Connection String exposée', 'critical'),
    (r'(?i)(redis://[^"\'\s]+)', 'Redis Connection String exposée', 'critical'),
    (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Clé privée exposée', 'critical'),
    (r'(?i)(stripe[_-]?secret[_-]?key|sk_live_)[a-zA-Z0-9]{20,}', 'Stripe Secret Key exposée', 'critical'),
    (r'(?i)sk_test_[a-zA-Z0-9]{20,}', 'Stripe Test Key exposée (attention en prod)', 'high'),
    (r'(?i)pk_live_[a-zA-Z0-9]{20,}', 'Stripe Public Key Live', 'medium'),
    (r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}', 'SendGrid API Key exposée', 'critical'),
    (r'(?i)twilio[_-]?(auth[_-]?token|api[_-]?key)\s*[=:]\s*["\']?[a-zA-Z0-9]{32}', 'Twilio Credentials exposées', 'critical'),
    (r'(?i)mailgun[_-]?api[_-]?key\s*[=:]\s*["\']?key-[a-zA-Z0-9]{32}', 'Mailgun API Key exposée', 'critical'),
    (r'(?i)firebase[_-]?api[_-]?key\s*[=:]\s*["\']?AIza[a-zA-Z0-9\-_]{35}', 'Firebase API Key exposée', 'high'),
    (r'AIza[a-zA-Z0-9\-_]{35}', 'Google API Key exposée', 'high'),
    (r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}', 'Bearer Token exposé', 'high'),
    (r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'JWT Token hardcodé', 'high'),
    (r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*["\']?[a-f0-9\-]{36}', 'Heroku API Key exposée', 'critical'),
    (r'(?i)digitalocean[_-]?(token|key)\s*[=:]\s*["\']?[a-f0-9]{64}', 'DigitalOcean Token exposé', 'critical'),
    (r'(?i)discord[_-]?(token|bot[_-]?token)\s*[=:]\s*["\']?[a-zA-Z0-9\-_\.]{50,}', 'Discord Token exposé', 'critical'),
    (r'(?i)telegram[_-]?bot[_-]?token\s*[=:]\s*["\']?\d+:[a-zA-Z0-9\-_]{35}', 'Telegram Bot Token exposé', 'critical'),
]

SQL_INJECTION_PATTERNS = [
    (r'execute\s*\(\s*["\'].*%s.*["\']', 'Injection SQL potentielle via string formatting', 'critical'),
    (r'execute\s*\(\s*f["\']', 'Injection SQL via f-string', 'critical'),
    (r'execute\s*\(\s*["\'].*\+\s*\w+', 'Injection SQL via concaténation', 'critical'),
    (r'cursor\.execute\s*\([^,]+\+', 'Injection SQL via concaténation cursor', 'critical'),
    (r'\.raw\s*\(\s*["\'].*%s', 'Raw SQL avec interpolation non sécurisée', 'high'),
    (r'\.extra\s*\(\s*where\s*=\s*\[.*%', 'Django extra() avec interpolation', 'high'),
    (r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+\s*\w+', 'SQL dynamique avec concaténation', 'critical'),
    (r'INSERT\s+INTO\s+.*VALUES\s*\(.*%s', 'INSERT avec string formatting', 'high'),
    (r'UPDATE\s+.*SET\s+.*=\s*.*%s', 'UPDATE avec string formatting', 'high'),
    (r'DELETE\s+FROM\s+.*WHERE\s+.*\+\s*\w+', 'DELETE avec concaténation', 'critical'),
    (r'\.query\s*\(\s*`[^`]*\$\{', 'Template literal SQL injection (Node.js)', 'critical'),
    (r'db\.query\s*\(\s*["\'].*\+', 'DB query avec concaténation', 'critical'),
    (r'sequelize\.query\s*\(\s*["\'].*\+', 'Sequelize raw query injection', 'critical'),
    (r'knex\.raw\s*\(\s*["\'].*\+', 'Knex raw query injection', 'critical'),
    (r'UNION\s+SELECT', 'Pattern UNION SELECT détecté', 'high'),
    (r';\s*DROP\s+TABLE', 'Pattern DROP TABLE détecté', 'critical'),
    (r'OR\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1', 'Pattern SQL injection classique', 'critical'),
]

XSS_PATTERNS = [
    (r'innerHTML\s*=\s*[^"\']*\+', 'XSS via innerHTML avec concaténation', 'high'),
    (r'innerHTML\s*=\s*[^;]*request', 'XSS via innerHTML avec user input', 'critical'),
    (r'document\.write\s*\([^)]*\+', 'XSS via document.write', 'high'),
    (r'document\.write\s*\([^)]*request', 'XSS via document.write avec user input', 'critical'),
    (r'\.html\s*\(\s*[^)]*\+', 'XSS via jQuery .html()', 'high'),
    (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML utilisé', 'medium'),
    (r'\|\s*safe\s*}}', 'Django/Jinja2 safe filter - XSS potentiel', 'medium'),
    (r'Markup\s*\(', 'Flask Markup sans échappement', 'medium'),
    (r'v-html\s*=', 'Vue v-html directive - XSS potentiel', 'medium'),
    (r'\[innerHTML\]\s*=', 'Angular innerHTML binding', 'medium'),
    (r'eval\s*\([^)]*\+', 'Eval avec concaténation', 'critical'),
    (r'eval\s*\([^)]*request', 'Eval avec user input', 'critical'),
    (r'Function\s*\([^)]*\+', 'Function constructor avec input', 'critical'),
    (r'new\s+Function\s*\(', 'Dynamic Function constructor', 'high'),
    (r'setTimeout\s*\(\s*[^,)]*\+', 'setTimeout avec string dynamique', 'high'),
    (r'setInterval\s*\(\s*[^,)]*\+', 'setInterval avec string dynamique', 'high'),
    (r'outerHTML\s*=', 'outerHTML assignment', 'medium'),
    (r'insertAdjacentHTML\s*\(', 'insertAdjacentHTML potentiellement dangereux', 'medium'),
    (r'document\.location\s*=\s*[^;]*\+', 'DOM-based redirect', 'high'),
    (r'window\.location\s*=\s*[^;]*request', 'Open redirect via user input', 'high'),
]

COMMAND_INJECTION_PATTERNS = [
    (r'os\.system\s*\([^)]*\+', 'Command injection via os.system', 'critical'),
    (r'os\.system\s*\([^)]*request', 'Command injection via os.system avec user input', 'critical'),
    (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'Subprocess avec shell=True', 'critical'),
    (r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True', 'Popen avec shell=True', 'critical'),
    (r'subprocess\.run\s*\([^)]*shell\s*=\s*True', 'subprocess.run avec shell=True', 'critical'),
    (r'exec\s*\([^)]*\+', 'Exec avec concaténation', 'critical'),
    (r'exec\s*\(\s*request\.', 'Exec avec user input', 'critical'),
    (r'eval\s*\(\s*request\.', 'Eval avec user input', 'critical'),
    (r'child_process\.exec\s*\([^)]*\+', 'Node exec avec concaténation', 'critical'),
    (r'child_process\.execSync\s*\([^)]*\+', 'Node execSync avec concaténation', 'critical'),
    (r'spawn\s*\([^)]*\+', 'Spawn avec concaténation', 'high'),
    (r'execFile\s*\([^)]*\+', 'execFile avec concaténation', 'high'),
    (r'Runtime\.getRuntime\(\)\.exec\s*\(', 'Java Runtime exec', 'high'),
    (r'ProcessBuilder\s*\([^)]*\+', 'Java ProcessBuilder injection', 'high'),
    (r'shell_exec\s*\(', 'PHP shell_exec', 'critical'),
    (r'passthru\s*\(', 'PHP passthru', 'critical'),
    (r'system\s*\(\s*\$', 'PHP system avec variable', 'critical'),
    (r'`[^`]*\$[^`]*`', 'Backtick command execution', 'high'),
]

PATH_TRAVERSAL_PATTERNS = [
    (r'open\s*\([^)]*\+', 'Path traversal potentiel via open()', 'high'),
    (r'open\s*\([^)]*request\.', 'Path traversal via user input', 'critical'),
    (r'os\.path\.join\s*\([^)]*request\.', 'Path traversal via user input', 'critical'),
    (r'send_file\s*\([^)]*\+', 'Path traversal via send_file', 'high'),
    (r'send_from_directory\s*\([^)]*\+', 'Path traversal via send_from_directory', 'high'),
    (r'\.\./', 'Path traversal pattern détecté', 'medium'),
    (r'readFile\s*\([^)]*\+', 'Node readFile avec concaténation', 'high'),
    (r'readFileSync\s*\([^)]*\+', 'Node readFileSync avec concaténation', 'high'),
    (r'fs\.createReadStream\s*\([^)]*\+', 'createReadStream avec concaténation', 'high'),
    (r'require\s*\([^)]*\+', 'Dynamic require (LFI potentiel)', 'high'),
    (r'import\s*\([^)]*\+', 'Dynamic import (LFI potentiel)', 'high'),
    (r'include\s*\(\s*\$', 'PHP include avec variable', 'critical'),
    (r'require\s*\(\s*\$', 'PHP require avec variable', 'critical'),
    (r'file_get_contents\s*\(\s*\$', 'PHP file_get_contents avec variable', 'high'),
]

INSECURE_DESERIALIZATION_PATTERNS = [
    (r'pickle\.loads?\s*\(', 'Désérialisation pickle non sécurisée', 'critical'),
    (r'pickle\.Unpickler\s*\(', 'Pickle Unpickler non sécurisé', 'critical'),
    (r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader', 'YAML load non sécurisé', 'high'),
    (r'yaml\.load\s*\([^)]*\)(?!.*SafeLoader)', 'YAML load sans SafeLoader', 'medium'),
    (r'yaml\.unsafe_load\s*\(', 'YAML unsafe_load', 'critical'),
    (r'marshal\.loads?\s*\(', 'Désérialisation marshal', 'high'),
    (r'unserialize\s*\(', 'PHP unserialize non sécurisé', 'critical'),
    (r'JSON\.parse\s*\([^)]*\)\s*\.\s*constructor', 'Prototype pollution potentielle', 'high'),
    (r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*[^)]*request', 'Prototype pollution via merge', 'high'),
    (r'\.merge\s*\([^)]*request', 'Deep merge prototype pollution', 'high'),
    (r'jsonpickle\.decode\s*\(', 'jsonpickle decode non sécurisé', 'critical'),
    (r'shelve\.open\s*\(', 'Shelve désérialisation non sécurisée', 'high'),
    (r'ObjectInputStream\s*\(', 'Java ObjectInputStream (désérialisation)', 'high'),
    (r'readObject\s*\(\s*\)', 'Java readObject désérialisation', 'high'),
]

INSECURE_CONFIG_PATTERNS = [
    (r'DEBUG\s*=\s*True', 'Mode DEBUG activé', 'high'),
    (r'FLASK_DEBUG\s*=\s*1', 'Flask DEBUG mode', 'high'),
    (r'FLASK_ENV\s*=\s*["\']?development', 'Flask en mode development', 'medium'),
    (r'NODE_ENV\s*[!=]=\s*["\']?production', 'Node.js pas en production', 'medium'),
    (r'verify\s*=\s*False', 'SSL verification désactivée', 'critical'),
    (r'ssl\s*=\s*False', 'SSL désactivé', 'critical'),
    (r'check_hostname\s*=\s*False', 'Hostname check désactivé', 'high'),
    (r'CORS\s*\(\s*\w+\s*,\s*resources\s*=.*\*', 'CORS trop permissif', 'medium'),
    (r'Access-Control-Allow-Origin.*\*', 'CORS wildcard', 'medium'),
    (r'Access-Control-Allow-Credentials.*true', 'CORS credentials avec wildcard', 'high'),
    (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', 'Secret key trop courte', 'high'),
    (r'SECRET_KEY\s*=\s*["\']changeme', 'Secret key par défaut', 'critical'),
    (r'SECRET_KEY\s*=\s*["\']secret', 'Secret key triviale', 'critical'),
    (r'allowedHosts\s*:\s*\[?\s*["\']?\*', 'allowedHosts wildcard', 'medium'),
    (r'ALLOWED_HOSTS\s*=\s*\[\s*["\']?\*', 'Django ALLOWED_HOSTS wildcard', 'high'),
    (r'SESSION_COOKIE_SECURE\s*=\s*False', 'Session cookie non sécurisé', 'high'),
    (r'CSRF_COOKIE_SECURE\s*=\s*False', 'CSRF cookie non sécurisé', 'high'),
    (r'httpOnly\s*:\s*false', 'Cookie httpOnly désactivé', 'high'),
    (r'secure\s*:\s*false', 'Cookie secure désactivé', 'high'),
    (r'sameSite\s*:\s*["\']?none', 'Cookie sameSite none', 'medium'),
    (r'X-Frame-Options.*ALLOWALL', 'X-Frame-Options permissif', 'high'),
    (r'Content-Security-Policy.*unsafe-inline', 'CSP avec unsafe-inline', 'medium'),
    (r'Content-Security-Policy.*unsafe-eval', 'CSP avec unsafe-eval', 'high'),
]

SSRF_PATTERNS = [
    (r'requests\.get\s*\([^)]*request\.', 'SSRF potentiel via requests', 'critical'),
    (r'requests\.post\s*\([^)]*request\.', 'SSRF potentiel via requests.post', 'critical'),
    (r'urllib\.request\.urlopen\s*\([^)]*\+', 'SSRF via urllib', 'critical'),
    (r'urllib\.urlopen\s*\([^)]*request\.', 'SSRF via urllib avec user input', 'critical'),
    (r'fetch\s*\([^)]*request\.', 'SSRF via fetch avec user input', 'critical'),
    (r'axios\s*\.\w+\s*\([^)]*request\.', 'SSRF via axios avec user input', 'critical'),
    (r'http\.get\s*\([^)]*\+', 'SSRF via http.get', 'high'),
    (r'curl_exec\s*\(', 'PHP curl_exec (SSRF potentiel)', 'medium'),
    (r'file_get_contents\s*\([^)]*http', 'PHP file_get_contents URL', 'high'),
]

CSRF_PATTERNS = [
    (r'@csrf_exempt', 'Django CSRF exempt décorateur', 'high'),
    (r'csrf_protect\s*=\s*False', 'CSRF protection désactivée', 'high'),
    (r'WTF_CSRF_ENABLED\s*=\s*False', 'Flask-WTF CSRF désactivé', 'critical'),
    (r'CSRF_ENABLED\s*=\s*False', 'CSRF désactivé', 'critical'),
    (r'@app\.route.*methods\s*=\s*\[[^]]*POST[^]]*\](?!.*csrf)', 'Route POST sans mention CSRF', 'medium'),
    (r'express\s*\(\s*\)(?!.*csrf)', 'Express sans middleware CSRF visible', 'low'),
]

AUTHENTICATION_PATTERNS = [
    (r'password\s*==\s*', 'Comparaison de mot de passe non sécurisée', 'critical'),
    (r'if\s+password\s*==', 'Comparaison directe de mot de passe', 'critical'),
    (r'md5\s*\(.*password', 'MD5 pour hachage de mot de passe', 'critical'),
    (r'sha1\s*\(.*password', 'SHA1 pour hachage de mot de passe', 'high'),
    (r'hashlib\.md5\s*\(', 'MD5 (obsolète pour sécurité)', 'high'),
    (r'hashlib\.sha1\s*\(', 'SHA1 (obsolète pour sécurité)', 'medium'),
    (r'\.createHash\s*\(\s*["\']md5', 'Node.js MD5 hash', 'high'),
    (r'\.createHash\s*\(\s*["\']sha1', 'Node.js SHA1 hash', 'medium'),
    (r'jwt\.decode\s*\([^)]*verify\s*=\s*False', 'JWT decode sans vérification', 'critical'),
    (r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[\s*\]', 'JWT sans algorithme spécifié', 'critical'),
    (r'algorithm\s*[=:]\s*["\']?none', 'JWT algorithm none', 'critical'),
    (r'expiresIn\s*:\s*["\']?\d+[dwy]', 'JWT expiration très longue', 'medium'),
    (r'@login_required(?!\s*\n.*@)', 'Décorateur login_required potentiellement manquant', 'info'),
]

HARDCODED_VALUES_PATTERNS = [
    (r'localhost:\d{4}', 'Localhost hardcodé', 'low'),
    (r'127\.0\.0\.1:\d{4}', 'IP localhost hardcodée', 'low'),
    (r'http://(?!localhost|127\.0\.0\.1)[^"\'\s]+', 'URL HTTP non sécurisée', 'medium'),
    (r'admin["\']?\s*:\s*["\']admin', 'Credentials admin par défaut', 'critical'),
    (r'root["\']?\s*:\s*["\']root', 'Credentials root par défaut', 'critical'),
    (r'username\s*=\s*["\']admin', 'Username admin hardcodé', 'high'),
    (r'password\s*=\s*["\']admin', 'Password admin hardcodé', 'critical'),
    (r'password\s*=\s*["\']password', 'Password trivial hardcodé', 'critical'),
    (r'password\s*=\s*["\']123456', 'Password 123456 hardcodé', 'critical'),
]

TOXIC_AI_PATTERNS_REGEX = [
    (r'# TODO:?\s*(fix|implement|add|complete|finish|later)', 'TODO non résolu', 'low'),
    (r'// TODO:?\s*(fix|implement|add|complete|finish|later)', 'TODO non résolu (JS)', 'low'),
    (r'# FIXME', 'FIXME non résolu', 'medium'),
    (r'// FIXME', 'FIXME non résolu (JS)', 'medium'),
    (r'# HACK', 'Code hack temporaire', 'medium'),
    (r'# XXX', 'XXX marker non résolu', 'medium'),
    (r'pass\s*# ?(placeholder|todo|implement|fix)', 'Placeholder pass statement', 'medium'),
    (r'raise NotImplementedError', 'Fonction non implémentée', 'medium'),
    (r'throw\s+new\s+Error\s*\(\s*["\']Not\s+implemented', 'Fonction non implémentée (JS)', 'medium'),
    (r'print\s*\(["\']debug', 'Debug print laissé', 'low'),
    (r'print\s*\(["\']test', 'Test print laissé', 'low'),
    (r'console\.log\s*\(["\']debug', 'Debug console.log', 'low'),
    (r'console\.log\s*\(["\']test', 'Test console.log', 'low'),
    (r'debugger;', 'Debugger statement laissé', 'medium'),
    (r'\.\.\..*# ?generated', 'Code généré non vérifié', 'medium'),
    (r'except:\s*pass', 'Exception silencieuse', 'high'),
    (r'except\s+Exception\s*:\s*pass', 'Exception générique silencieuse', 'high'),
    (r'except\s+Exception\s+as\s+\w+:\s*pass', 'Exception capturée mais ignorée', 'high'),
    (r'catch\s*\(\s*\w*\s*\)\s*\{\s*\}', 'Catch block vide', 'high'),
    (r'# AI generated|# Generated by|# Auto-generated', 'Code AI non optimisé potentiel', 'info'),
    (r'// AI generated|// Generated by|// Auto-generated', 'Code AI non optimisé potentiel (JS)', 'info'),
    (r'# copilot|# chatgpt|# claude', 'Code généré par IA', 'info'),
    (r'def\s+\w+\s*\([^)]*\)\s*:\s*\.\.\.\s*$', 'Fonction stub incomplète', 'medium'),
    (r'return\s+None\s*# ?todo', 'Return placeholder', 'medium'),
    (r'return\s+\[\s*\]\s*# ?todo', 'Return liste vide placeholder', 'medium'),
    (r'return\s+\{\s*\}\s*# ?todo', 'Return dict vide placeholder', 'medium'),
]

PERFORMANCE_PATTERNS = [
    (r'while\s+True\s*:', 'Boucle infinie potentielle', 'medium'),
    (r'while\s*\(\s*true\s*\)', 'Boucle infinie potentielle (JS)', 'medium'),
    (r'for\s+\w+\s+in\s+\w+\.objects\.all\(\)', 'Query N+1 potentielle Django', 'high'),
    (r'\.objects\.get\s*\([^)]*\).*for', 'N+1 query dans boucle', 'high'),
    (r'\.objects\.filter.*for.*\.objects\.(get|filter)', 'Nested queries N+1', 'high'),
    (r'time\.sleep\s*\(\s*\d{2,}\s*\)', 'Sleep long bloquant', 'medium'),
    (r'Thread\.sleep\s*\(\s*\d{4,}\s*\)', 'Thread.sleep très long', 'medium'),
    (r'\+\s*=\s*["\']', 'Concaténation string dans boucle', 'low'),
    (r'global\s+\w+', 'Variable globale utilisée', 'low'),
    (r'SELECT\s+\*\s+FROM', 'SELECT * non optimisé', 'low'),
    (r'SELECT\s+.*FROM\s+\w+\s*;(?!.*LIMIT)', 'SELECT sans LIMIT', 'low'),
    (r'\.findAll\s*\(\s*\)', 'findAll sans conditions', 'medium'),
    (r'\.find\s*\(\s*\{\s*\}\s*\)', 'MongoDB find vide', 'medium'),
    (r'recursion|recursive(?!.*@cache|.*lru_cache)', 'Récursion sans cache', 'low'),
    (r'\.map\s*\([^)]*\)\s*\.filter\s*\(', 'Map puis filter (inefficace)', 'low'),
    (r'\.forEach\s*\([^)]*await', 'Await dans forEach (non parallèle)', 'medium'),
    (r'Promise\.all\s*\(\s*\[\s*\]\s*\.map', 'Promise.all sans limite de concurrence', 'low'),
]

LANGUAGE_EXTENSIONS = {
    '.py': 'Python',
    '.pyx': 'Cython',
    '.pyi': 'Python (stubs)',
    '.js': 'JavaScript',
    '.mjs': 'JavaScript (ESM)',
    '.cjs': 'JavaScript (CommonJS)',
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript (React)',
    '.jsx': 'JavaScript (React)',
    '.java': 'Java',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.rs': 'Rust',
    '.cpp': 'C++',
    '.cc': 'C++',
    '.cxx': 'C++',
    '.c': 'C',
    '.h': 'C/C++ Header',
    '.hpp': 'C++ Header',
    '.cs': 'C#',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.kts': 'Kotlin Script',
    '.scala': 'Scala',
    '.vue': 'Vue.js',
    '.svelte': 'Svelte',
    '.dart': 'Dart',
    '.ex': 'Elixir',
    '.exs': 'Elixir Script',
    '.erl': 'Erlang',
    '.clj': 'Clojure',
    '.cljs': 'ClojureScript',
    '.hs': 'Haskell',
    '.ml': 'OCaml',
    '.fs': 'F#',
    '.r': 'R',
    '.R': 'R',
    '.pl': 'Perl',
    '.pm': 'Perl Module',
    '.lua': 'Lua',
    '.jl': 'Julia',
    '.nim': 'Nim',
    '.zig': 'Zig',
    '.v': 'V',
    '.cr': 'Crystal',
    '.groovy': 'Groovy',
    '.gradle': 'Gradle',
}

FRAMEWORK_DETECTION = {
    'Python': {
        'Django': {
            'files': ['manage.py', 'settings.py', 'urls.py', 'wsgi.py', 'asgi.py'],
            'patterns': [r'from django', r'import django', r'INSTALLED_APPS', r'MIDDLEWARE', r'DATABASES'],
            'config_files': ['settings.py', 'django.cfg'],
            'weight': 5
        },
        'Flask': {
            'files': ['app.py', 'wsgi.py'],
            'patterns': [r'from flask import', r'Flask\s*\(', r'@app\.route', r'Blueprint\s*\('],
            'config_files': ['config.py'],
            'weight': 4
        },
        'FastAPI': {
            'files': ['main.py'],
            'patterns': [r'from fastapi import', r'FastAPI\s*\(', r'@app\.(get|post|put|delete|patch)', r'Depends\s*\('],
            'config_files': [],
            'weight': 4
        },
        'Pyramid': {
            'files': ['development.ini', 'production.ini'],
            'patterns': [r'from pyramid', r'config\.add_route', r'Configurator\s*\('],
            'config_files': ['development.ini'],
            'weight': 3
        },
        'Tornado': {
            'files': [],
            'patterns': [r'from tornado', r'tornado\.web', r'RequestHandler', r'IOLoop'],
            'config_files': [],
            'weight': 3
        },
        'Celery': {
            'files': ['celery.py', 'tasks.py'],
            'patterns': [r'from celery import', r'Celery\s*\(', r'@app\.task', r'@shared_task'],
            'config_files': ['celeryconfig.py'],
            'weight': 2
        },
        'SQLAlchemy': {
            'files': [],
            'patterns': [r'from sqlalchemy', r'create_engine', r'declarative_base', r'Column\s*\(', r'relationship\s*\('],
            'config_files': [],
            'weight': 2
        },
        'Pandas': {
            'files': [],
            'patterns': [r'import pandas', r'pd\.DataFrame', r'pd\.read_csv', r'\.to_csv\('],
            'config_files': [],
            'weight': 1
        },
        'NumPy': {
            'files': [],
            'patterns': [r'import numpy', r'np\.array', r'np\.zeros', r'np\.ones'],
            'config_files': [],
            'weight': 1
        },
        'TensorFlow': {
            'files': [],
            'patterns': [r'import tensorflow', r'tf\.keras', r'tf\.constant', r'tf\.Variable'],
            'config_files': [],
            'weight': 2
        },
        'PyTorch': {
            'files': [],
            'patterns': [r'import torch', r'torch\.nn', r'torch\.tensor', r'nn\.Module'],
            'config_files': [],
            'weight': 2
        },
        'Streamlit': {
            'files': [],
            'patterns': [r'import streamlit', r'st\.write', r'st\.title', r'st\.button'],
            'config_files': ['.streamlit/config.toml'],
            'weight': 2
        },
    },
    'JavaScript': {
        'React': {
            'files': [],
            'patterns': [r'from ["\']react["\']', r'import React', r'useState', r'useEffect', r'ReactDOM', r'createRoot'],
            'config_files': [],
            'package_deps': ['react', 'react-dom'],
            'weight': 5
        },
        'Next.js': {
            'files': ['next.config.js', 'next.config.mjs', 'pages/_app.js', 'app/layout.tsx'],
            'patterns': [r'from ["\']next', r'getServerSideProps', r'getStaticProps', r'useRouter'],
            'config_files': ['next.config.js', 'next.config.mjs'],
            'package_deps': ['next'],
            'weight': 5
        },
        'Vue.js': {
            'files': ['vue.config.js', 'nuxt.config.js'],
            'patterns': [r'from ["\']vue["\']', r'createApp', r'defineComponent', r'ref\s*\(', r'reactive\s*\('],
            'config_files': ['vue.config.js'],
            'package_deps': ['vue'],
            'weight': 5
        },
        'Nuxt.js': {
            'files': ['nuxt.config.js', 'nuxt.config.ts'],
            'patterns': [r'defineNuxtConfig', r'useNuxtApp', r'useFetch'],
            'config_files': ['nuxt.config.js', 'nuxt.config.ts'],
            'package_deps': ['nuxt'],
            'weight': 5
        },
        'Angular': {
            'files': ['angular.json', 'angular-cli.json'],
            'patterns': [r'@angular/core', r'@Component', r'@NgModule', r'@Injectable'],
            'config_files': ['angular.json'],
            'package_deps': ['@angular/core'],
            'weight': 5
        },
        'Express.js': {
            'files': [],
            'patterns': [r'require\s*\(\s*["\']express["\']', r'from ["\']express["\']', r'app\.get\s*\(', r'app\.post\s*\(', r'Router\s*\(\s*\)'],
            'config_files': [],
            'package_deps': ['express'],
            'weight': 4
        },
        'NestJS': {
            'files': ['nest-cli.json'],
            'patterns': [r'@nestjs/core', r'@Module', r'@Controller', r'@Injectable', r'@Get', r'@Post'],
            'config_files': ['nest-cli.json'],
            'package_deps': ['@nestjs/core'],
            'weight': 4
        },
        'Fastify': {
            'files': [],
            'patterns': [r'require\s*\(\s*["\']fastify["\']', r'from ["\']fastify["\']', r'fastify\s*\(\s*\)'],
            'config_files': [],
            'package_deps': ['fastify'],
            'weight': 3
        },
        'Svelte': {
            'files': ['svelte.config.js'],
            'patterns': [r'<script>', r'\$:', r'on:click', r'bind:'],
            'config_files': ['svelte.config.js'],
            'package_deps': ['svelte'],
            'weight': 4
        },
        'SvelteKit': {
            'files': ['svelte.config.js', 'src/routes'],
            'patterns': [r'from ["\']@sveltejs/kit["\']', r'\+page\.svelte', r'\+layout\.svelte'],
            'config_files': ['svelte.config.js'],
            'package_deps': ['@sveltejs/kit'],
            'weight': 5
        },
        'Electron': {
            'files': ['main.js', 'preload.js'],
            'patterns': [r'require\s*\(\s*["\']electron["\']', r'BrowserWindow', r'ipcMain', r'ipcRenderer'],
            'config_files': [],
            'package_deps': ['electron'],
            'weight': 3
        },
        'React Native': {
            'files': ['app.json', 'metro.config.js'],
            'patterns': [r'react-native', r'AppRegistry', r'StyleSheet\.create'],
            'config_files': ['app.json', 'metro.config.js'],
            'package_deps': ['react-native'],
            'weight': 4
        },
    },
    'TypeScript': {
        'inherit': 'JavaScript'
    },
    'Ruby': {
        'Rails': {
            'files': ['Gemfile', 'config/routes.rb', 'config/application.rb', 'bin/rails'],
            'patterns': [r'Rails\.application', r'ActiveRecord', r'ApplicationController', r'has_many', r'belongs_to'],
            'config_files': ['config/application.rb', 'config/database.yml'],
            'weight': 5
        },
        'Sinatra': {
            'files': [],
            'patterns': [r'require\s*["\']sinatra["\']', r'Sinatra::Base', r'get\s*["\']/', r'post\s*["\']'],
            'config_files': [],
            'weight': 3
        },
        'Hanami': {
            'files': [],
            'patterns': [r'require\s*["\']hanami["\']', r'Hanami::Application'],
            'config_files': [],
            'weight': 3
        },
    },
    'PHP': {
        'Laravel': {
            'files': ['artisan', 'composer.json'],
            'patterns': [r'Illuminate\\', r'use App\\', r'Route::', r'Eloquent', r'Blade::'],
            'config_files': ['config/app.php', '.env'],
            'weight': 5
        },
        'Symfony': {
            'files': ['symfony.lock', 'bin/console'],
            'patterns': [r'Symfony\\', r'use Doctrine\\', r'AbstractController'],
            'config_files': ['config/services.yaml'],
            'weight': 5
        },
        'CodeIgniter': {
            'files': ['spark'],
            'patterns': [r'CI_Controller', r'CodeIgniter'],
            'config_files': [],
            'weight': 3
        },
        'WordPress': {
            'files': ['wp-config.php', 'wp-content'],
            'patterns': [r'wp_enqueue', r'add_action', r'add_filter', r'WP_Query'],
            'config_files': ['wp-config.php'],
            'weight': 4
        },
    },
    'Go': {
        'Gin': {
            'files': [],
            'patterns': [r'github\.com/gin-gonic/gin', r'gin\.Default\(\)', r'gin\.New\(\)', r'c\.JSON\('],
            'config_files': [],
            'weight': 4
        },
        'Echo': {
            'files': [],
            'patterns': [r'github\.com/labstack/echo', r'echo\.New\(\)', r'c\.JSON\('],
            'config_files': [],
            'weight': 4
        },
        'Fiber': {
            'files': [],
            'patterns': [r'github\.com/gofiber/fiber', r'fiber\.New\(\)', r'c\.JSON\('],
            'config_files': [],
            'weight': 4
        },
        'GORM': {
            'files': [],
            'patterns': [r'gorm\.io/gorm', r'gorm\.Open\(', r'db\.Create\(', r'db\.Find\('],
            'config_files': [],
            'weight': 2
        },
    },
    'Rust': {
        'Actix-web': {
            'files': [],
            'patterns': [r'actix_web', r'HttpServer::new', r'web::get', r'web::post'],
            'config_files': [],
            'weight': 4
        },
        'Rocket': {
            'files': [],
            'patterns': [r'#\[macro_use\]\s*extern\s*crate\s*rocket', r'rocket::ignite', r'#\[get\(', r'#\[post\('],
            'config_files': ['Rocket.toml'],
            'weight': 4
        },
        'Axum': {
            'files': [],
            'patterns': [r'axum::', r'Router::new', r'axum::routing'],
            'config_files': [],
            'weight': 4
        },
        'Tokio': {
            'files': [],
            'patterns': [r'tokio::', r'#\[tokio::main\]', r'async fn', r'\.await'],
            'config_files': [],
            'weight': 2
        },
    },
    'Java': {
        'Spring Boot': {
            'files': ['pom.xml', 'build.gradle'],
            'patterns': [r'@SpringBootApplication', r'@RestController', r'@Autowired', r'@Service', r'@Repository'],
            'config_files': ['application.properties', 'application.yml'],
            'weight': 5
        },
        'Spring MVC': {
            'files': [],
            'patterns': [r'@Controller', r'@RequestMapping', r'ModelAndView'],
            'config_files': [],
            'weight': 4
        },
        'Hibernate': {
            'files': [],
            'patterns': [r'org\.hibernate', r'@Entity', r'@Table', r'SessionFactory'],
            'config_files': ['hibernate.cfg.xml'],
            'weight': 3
        },
        'Maven': {
            'files': ['pom.xml'],
            'patterns': [],
            'config_files': ['pom.xml'],
            'weight': 1
        },
        'Gradle': {
            'files': ['build.gradle', 'build.gradle.kts', 'settings.gradle'],
            'patterns': [],
            'config_files': ['build.gradle', 'build.gradle.kts'],
            'weight': 1
        },
    },
    'C#': {
        'ASP.NET Core': {
            'files': ['Program.cs', 'Startup.cs'],
            'patterns': [r'Microsoft\.AspNetCore', r'WebApplication\.Create', r'IHostBuilder', r'\[ApiController\]', r'\[HttpGet\]'],
            'config_files': ['appsettings.json'],
            'weight': 5
        },
        'Entity Framework': {
            'files': [],
            'patterns': [r'Microsoft\.EntityFrameworkCore', r'DbContext', r'DbSet<'],
            'config_files': [],
            'weight': 3
        },
        'Blazor': {
            'files': [],
            'patterns': [r'@page', r'@inject', r'@code', r'Microsoft\.AspNetCore\.Components'],
            'config_files': [],
            'weight': 4
        },
    },
}

SENSITIVE_FILES_GIT = [
    '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
    '.env.test', '.envrc',
    'config.json', 'secrets.json', 'credentials.json', 'auth.json',
    '.htpasswd', '.htaccess',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    '*.pem', '*.key', '*.p12', '*.pfx', '*.jks', '*.keystore',
    'wp-config.php', 'database.yml', 'database.json',
    '.npmrc', '.pypirc', '.netrc', '.docker/config.json',
    'serviceAccountKey.json', 'firebase-adminsdk*.json',
    'google-credentials.json', 'gcp-credentials.json',
    'terraform.tfstate', 'terraform.tfvars',
    '.aws/credentials', '.aws/config',
    'kubeconfig', '.kube/config',
    'docker-compose.override.yml',
]

VULNERABLE_PACKAGES = {
    'python': {
        'pyyaml': {'vulnerable_versions': ['<5.4'], 'cve': 'CVE-2020-14343', 'severity': 'critical'},
        'django': {'vulnerable_versions': ['<3.2.14', '<4.0.6'], 'cve': 'CVE-2022-34265', 'severity': 'high'},
        'flask': {'vulnerable_versions': ['<2.3.2'], 'cve': 'CVE-2023-30861', 'severity': 'high'},
        'jinja2': {'vulnerable_versions': ['<3.1.2'], 'cve': 'CVE-2024-22195', 'severity': 'medium'},
        'requests': {'vulnerable_versions': ['<2.31.0'], 'cve': 'CVE-2023-32681', 'severity': 'medium'},
        'pillow': {'vulnerable_versions': ['<10.0.1'], 'cve': 'CVE-2023-44271', 'severity': 'high'},
        'cryptography': {'vulnerable_versions': ['<41.0.0'], 'cve': 'CVE-2023-38325', 'severity': 'medium'},
        'urllib3': {'vulnerable_versions': ['<2.0.6'], 'cve': 'CVE-2023-45803', 'severity': 'medium'},
        'werkzeug': {'vulnerable_versions': ['<3.0.1'], 'cve': 'CVE-2023-46136', 'severity': 'high'},
        'sqlalchemy': {'vulnerable_versions': ['<2.0.0'], 'cve': 'Multiple', 'severity': 'medium'},
    },
    'npm': {
        'express': {'vulnerable_versions': ['<4.18.2'], 'cve': 'CVE-2022-24999', 'severity': 'high'},
        'lodash': {'vulnerable_versions': ['<4.17.21'], 'cve': 'CVE-2021-23337', 'severity': 'high'},
        'axios': {'vulnerable_versions': ['<1.6.0'], 'cve': 'CVE-2023-45857', 'severity': 'medium'},
        'jsonwebtoken': {'vulnerable_versions': ['<9.0.0'], 'cve': 'CVE-2022-23529', 'severity': 'critical'},
        'minimist': {'vulnerable_versions': ['<1.2.6'], 'cve': 'CVE-2021-44906', 'severity': 'critical'},
        'node-fetch': {'vulnerable_versions': ['<2.6.7', '<3.1.1'], 'cve': 'CVE-2022-0235', 'severity': 'high'},
        'qs': {'vulnerable_versions': ['<6.10.3'], 'cve': 'CVE-2022-24999', 'severity': 'high'},
        'shell-quote': {'vulnerable_versions': ['<1.7.3'], 'cve': 'CVE-2021-42740', 'severity': 'critical'},
        'moment': {'vulnerable_versions': ['<2.29.4'], 'cve': 'CVE-2022-31129', 'severity': 'high'},
        'xml2js': {'vulnerable_versions': ['<0.5.0'], 'cve': 'CVE-2023-0842', 'severity': 'medium'},
    },
}

SEVERITY_SCORES = {
    'info': 0,
    'low': 1,
    'medium': 3,
    'high': 6,
    'critical': 10
}

SECURITY_WEIGHT = 0.55
DEPENDENCIES_WEIGHT = 0.12
ARCHITECTURE_WEIGHT = 0.08
TOXIC_AI_WEIGHT = 0.08
PERFORMANCE_WEIGHT = 0.07
GIT_QUALITY_WEIGHT = 0.05
DOCUMENTATION_WEIGHT = 0.05
