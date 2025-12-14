import os
import re
import json
import math
import shutil
import tempfile
import subprocess
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import requests


class GitHubCodeAnalyzerService:
    
    SECURITY_WEIGHT = 0.55
    DEPENDENCIES_WEIGHT = 0.12
    ARCHITECTURE_WEIGHT = 0.08
    TOXIC_AI_WEIGHT = 0.08
    PERFORMANCE_WEIGHT = 0.07
    GIT_QUALITY_WEIGHT = 0.05
    DOCUMENTATION_WEIGHT = 0.05
    
    SEVERITY_SCORES = {
        'info': 0,
        'low': 1,
        'medium': 3,
        'high': 6,
        'critical': 10
    }
    
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
    
    def __init__(self):
        self.temp_dir = None
        self.findings = {
            'security': [],
            'dependencies': [],
            'architecture': [],
            'performance': [],
            'git_hygiene': [],
            'documentation': [],
            'toxic_ai': [],
            'code_quality': []
        }
        self.stats = {
            'total_files': 0,
            'total_lines': 0,
            'languages': defaultdict(int),
            'frameworks': defaultdict(lambda: {'score': 0, 'evidence': []}),
            'detected_frameworks': set(),
            'package_json': None,
            'requirements_txt': None,
        }
        self.file_hashes = {}
    
    def analyze(self, repo_url, branch='main'):
        start_time = time.time()
        
        try:
            parsed = urlparse(repo_url)
            if parsed.netloc not in ['github.com', 'www.github.com']:
                return {
                    'error': True,
                    'message': 'Seuls les dépôts GitHub sont supportés'
                }
            
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) < 2:
                return {
                    'error': True,
                    'message': 'URL GitHub invalide. Format attendu: https://github.com/owner/repo'
                }
            
            owner = path_parts[0]
            repo_name = path_parts[1].replace('.git', '')
            
            self.temp_dir = tempfile.mkdtemp(prefix='github_analysis_')
            
            clone_result = self._clone_repository(repo_url, branch)
            if clone_result.get('error'):
                return clone_result
            
            commit_hash = self._get_commit_hash()
            
            self._load_package_manifests()
            
            self._analyze_all_files()
            
            self._analyze_git_history()
            
            self._analyze_dependencies()
            
            self._analyze_architecture()
            
            self._analyze_documentation()
            
            self._finalize_framework_detection()
            
            scores = self._calculate_scores()
            
            duration = time.time() - start_time
            
            return {
                'error': False,
                'repo_url': repo_url,
                'repo_name': repo_name,
                'repo_owner': owner,
                'branch': branch,
                'commit_hash': commit_hash,
                'overall_score': scores['overall'],
                'security_score': scores['security'],
                'dependency_score': scores['dependencies'],
                'architecture_score': scores['architecture'],
                'performance_score': scores['performance'],
                'documentation_score': scores['documentation'],
                'risk_level': scores['risk_level'],
                'security_findings': self.findings['security'],
                'dependency_findings': self.findings['dependencies'],
                'architecture_findings': self.findings['architecture'],
                'performance_findings': self.findings['performance'],
                'git_hygiene_findings': self.findings['git_hygiene'],
                'documentation_findings': self.findings['documentation'],
                'toxic_ai_patterns': self.findings['toxic_ai'],
                'code_quality_findings': self.findings['code_quality'],
                'total_files_analyzed': self.stats['total_files'],
                'total_lines_analyzed': self.stats['total_lines'],
                'total_issues_found': sum(len(f) for f in self.findings.values()),
                'critical_issues': self._count_by_severity('critical'),
                'high_issues': self._count_by_severity('high'),
                'medium_issues': self._count_by_severity('medium'),
                'low_issues': self._count_by_severity('low'),
                'languages_detected': dict(self.stats['languages']),
                'primary_language': self._get_primary_language(),
                'frameworks_detected': list(self.stats['detected_frameworks']),
                'framework_details': self._get_framework_details(),
                'analysis_duration': round(duration, 2),
                'analysis_summary': self._generate_summary(scores),
                'security_summary': self._generate_security_summary(),
                'recommendations': self._generate_recommendations()
            }
            
        except Exception as e:
            import traceback
            return {
                'error': True,
                'message': f'Erreur lors de l\'analyse: {str(e)}',
                'traceback': traceback.format_exc()
            }
        finally:
            self._cleanup()
    
    def _clone_repository(self, repo_url, branch):
        if not self.temp_dir:
            return {'error': True, 'message': 'Répertoire temporaire non initialisé'}
        try:
            api_url = repo_url.replace('github.com', 'api.github.com/repos').rstrip('/')
            if api_url.endswith('.git'):
                api_url = api_url[:-4]
            
            headers = {'Accept': 'application/vnd.github.v3+json'}
            
            try:
                response = requests.get(api_url, headers=headers, timeout=10)
                if response.status_code == 404:
                    return {'error': True, 'message': 'Dépôt non trouvé ou privé'}
                elif response.status_code != 200:
                    pass
            except:
                pass
            
            result = subprocess.run(
                ['git', 'clone', '--depth', '100', '--single-branch', '-b', branch, repo_url, self.temp_dir],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode != 0:
                if 'not found' in result.stderr.lower():
                    return {'error': True, 'message': f'Branche "{branch}" non trouvée. Essayez "main" ou "master".'}
                return {'error': True, 'message': f'Erreur de clonage: {result.stderr}'}
            
            return {'error': False}
            
        except subprocess.TimeoutExpired:
            return {'error': True, 'message': 'Timeout lors du clonage (dépôt trop volumineux)'}
        except Exception as e:
            return {'error': True, 'message': f'Erreur de clonage: {str(e)}'}
    
    def _get_commit_hash(self):
        if not self.temp_dir:
            return 'unknown'
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()[:8]
        except:
            return 'unknown'
    
    def _load_package_manifests(self):
        if not self.temp_dir:
            return
        package_json_path = os.path.join(self.temp_dir, 'package.json')
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r', encoding='utf-8') as f:
                    self.stats['package_json'] = json.load(f)
            except:
                pass
        
        requirements_path = os.path.join(self.temp_dir, 'requirements.txt')
        if os.path.exists(requirements_path):
            try:
                with open(requirements_path, 'r', encoding='utf-8') as f:
                    self.stats['requirements_txt'] = f.read()
            except:
                pass
    
    def _analyze_all_files(self):
        if not self.temp_dir:
            return
        excluded_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 
                        '.venv', 'vendor', 'dist', 'build', '.next', 'coverage',
                        '.cache', '.pytest_cache', '.mypy_cache', 'target',
                        'bower_components', '.nuxt', '.output', 'out'}
        excluded_extensions = {'.min.js', '.min.css', '.map', '.lock', '.svg', 
                              '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', 
                              '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
                              '.avi', '.mov', '.webm', '.pdf', '.zip', '.tar',
                              '.gz', '.rar', '.7z', '.exe', '.dll', '.so',
                              '.pyc', '.pyo', '.class', '.jar', '.war'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            
            for filename in files:
                if any(filename.endswith(ext) for ext in excluded_extensions):
                    continue
                
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, self.temp_dir)
                
                _, ext = os.path.splitext(filename)
                ext_lower = ext.lower()
                
                if ext_lower in self.LANGUAGE_EXTENSIONS:
                    self.stats['languages'][self.LANGUAGE_EXTENSIONS[ext_lower]] += 1
                
                self.stats['total_files'] += 1
                
                try:
                    file_size = os.path.getsize(filepath)
                    if file_size > 1024 * 1024:
                        continue
                    
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        self.stats['total_lines'] += len(lines)
                        
                        self._detect_frameworks_advanced(content, filename, relative_path)
                        
                        self._scan_for_secrets(content, relative_path)
                        self._scan_sql_injection(content, relative_path)
                        self._scan_xss(content, relative_path)
                        self._scan_command_injection(content, relative_path)
                        self._scan_path_traversal(content, relative_path)
                        self._scan_insecure_deserialization(content, relative_path)
                        self._scan_insecure_config(content, relative_path)
                        self._scan_ssrf(content, relative_path)
                        self._scan_csrf(content, relative_path)
                        self._scan_authentication_issues(content, relative_path)
                        self._scan_hardcoded_values(content, relative_path)
                        
                        self._scan_toxic_ai_patterns(content, relative_path)
                        
                        self._scan_performance_issues(content, relative_path)
                        
                        self._analyze_code_quality(content, relative_path, ext_lower)
                        
                except Exception as e:
                    continue
    
    def _detect_frameworks_advanced(self, content, filename, filepath):
        primary_lang = self._get_primary_language()
        
        for lang, frameworks in self.FRAMEWORK_DETECTION.items():
            if frameworks == {'inherit': 'JavaScript'}:
                frameworks = self.FRAMEWORK_DETECTION.get('JavaScript', {})
            
            for framework_name, detection in frameworks.items():
                score = 0
                evidence = []
                
                if filename in detection.get('files', []):
                    score += 3
                    evidence.append(f'Fichier caractéristique: {filename}')
                
                for pattern in detection.get('patterns', []):
                    if re.search(pattern, content, re.IGNORECASE):
                        score += 2
                        evidence.append(f'Pattern détecté: {pattern[:30]}...')
                        if score >= 4:
                            break
                
                if self.stats.get('package_json'):
                    pkg_deps = {
                        **self.stats['package_json'].get('dependencies', {}),
                        **self.stats['package_json'].get('devDependencies', {})
                    }
                    for dep in detection.get('package_deps', []):
                        if dep in pkg_deps:
                            score += 4
                            evidence.append(f'Dépendance package.json: {dep}')
                
                if score > 0:
                    self.stats['frameworks'][framework_name]['score'] += score
                    self.stats['frameworks'][framework_name]['evidence'].extend(evidence)
    
    def _finalize_framework_detection(self):
        for framework, data in self.stats['frameworks'].items():
            if data['score'] >= 4:
                self.stats['detected_frameworks'].add(framework)
    
    def _get_framework_details(self):
        details = {}
        for framework in self.stats['detected_frameworks']:
            data = self.stats['frameworks'].get(framework, {})
            details[framework] = {
                'confidence_score': min(data.get('score', 0), 10),
                'evidence': list(set(data.get('evidence', [])))[:5]
            }
        return details
    
    def _get_primary_language(self):
        if not self.stats['languages']:
            return 'Unknown'
        return max(self.stats['languages'].items(), key=lambda x: x[1])[0]
    
    def _scan_for_secrets(self, content, filepath):
        for pattern, description, severity in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_false_positive_secret(match.group(0), filepath):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'secret_exposed',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': self._redact_secret(match.group(0)),
                    'category': 'Secrets & Credentials',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'remediation': 'Supprimez le secret du code et utilisez des variables d\'environnement ou un gestionnaire de secrets'
                })
    
    def _is_false_positive_secret(self, match, filepath):
        false_positive_patterns = [
            r'example', r'placeholder', r'your[_-]?api[_-]?key', r'xxx+',
            r'test[_-]?key', r'fake[_-]?key', r'dummy', r'sample',
            r'<your', r'\[your', r'\{your', r'INSERT_', r'REPLACE_',
            r'process\.env', r'os\.environ', r'getenv', r'env\[',
        ]
        match_lower = match.lower()
        for fp in false_positive_patterns:
            if re.search(fp, match_lower):
                return True
        
        if any(x in filepath.lower() for x in ['test', 'spec', 'mock', 'fixture', 'example', 'sample', 'doc']):
            return True
        
        return False
    
    def _scan_sql_injection(self, content, filepath):
        for pattern, description, severity in self.SQL_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'sql_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Injection',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Utilisez des requêtes paramétrées ou un ORM avec des paramètres typés'
                })
    
    def _scan_xss(self, content, filepath):
        for pattern, description, severity in self.XSS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'xss',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Cross-Site Scripting',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Échappez toujours les données utilisateur avant l\'affichage HTML'
                })
    
    def _scan_command_injection(self, content, filepath):
        for pattern, description, severity in self.COMMAND_INJECTION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'command_injection',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Command Injection',
                    'owasp': 'A03:2021 - Injection',
                    'remediation': 'Évitez shell=True et utilisez des listes de commandes avec validation stricte des entrées'
                })
    
    def _scan_path_traversal(self, content, filepath):
        for pattern, description, severity in self.PATH_TRAVERSAL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'path_traversal',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Path Traversal',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'remediation': 'Validez et normalisez les chemins de fichiers, utilisez une whitelist de répertoires autorisés'
                })
    
    def _scan_insecure_deserialization(self, content, filepath):
        for pattern, description, severity in self.INSECURE_DESERIALIZATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'insecure_deserialization',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Insecure Deserialization',
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'remediation': 'Utilisez des formats de sérialisation sécurisés (JSON) ou des loaders sécurisés (SafeLoader pour YAML)'
                })
    
    def _scan_insecure_config(self, content, filepath):
        for pattern, description, severity in self.INSECURE_CONFIG_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'insecure_config',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Security Misconfiguration',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'remediation': 'Vérifiez et sécurisez la configuration pour la production'
                })
    
    def _scan_ssrf(self, content, filepath):
        for pattern, description, severity in self.SSRF_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'ssrf',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Server-Side Request Forgery',
                    'owasp': 'A10:2021 - Server-Side Request Forgery',
                    'remediation': 'Validez et sanitisez les URLs, utilisez une whitelist de domaines autorisés'
                })
    
    def _scan_csrf(self, content, filepath):
        for pattern, description, severity in self.CSRF_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'csrf',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Cross-Site Request Forgery',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'remediation': 'Implémentez une protection CSRF avec des tokens'
                })
    
    def _scan_authentication_issues(self, content, filepath):
        for pattern, description, severity in self.AUTHENTICATION_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'authentication_issue',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Authentication Failures',
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'remediation': 'Utilisez des fonctions de hachage sécurisées (bcrypt, Argon2) et des comparaisons à temps constant'
                })
    
    def _scan_hardcoded_values(self, content, filepath):
        for pattern, description, severity in self.HARDCODED_VALUES_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if self._is_false_positive_secret(match.group(0), filepath):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                self.findings['security'].append({
                    'type': 'hardcoded_value',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'category': 'Hardcoded Values',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'remediation': 'Utilisez des variables d\'environnement ou des fichiers de configuration externes'
                })
    
    def _scan_toxic_ai_patterns(self, content, filepath):
        for pattern, description, severity in self.TOXIC_AI_PATTERNS_REGEX:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['toxic_ai'].append({
                    'type': 'toxic_ai_pattern',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Révisez et complétez le code généré par l\'IA'
                })
        
        self._detect_duplicate_functions(content, filepath)
        self._detect_inconsistent_logic(content, filepath)
    
    def _detect_duplicate_functions(self, content, filepath):
        func_pattern = r'(def\s+(\w+)|function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*:\s*(?:async\s*)?function)'
        matches = list(re.finditer(func_pattern, content))
        
        seen = defaultdict(list)
        for match in matches:
            groups = match.groups()
            name = next((g for g in groups[1:] if g), None)
            if name and name not in ['__init__', 'constructor', 'render', 'get', 'set', 'delete', 'update', 'create']:
                line_num = content[:match.start()].count('\n') + 1
                seen[name].append(line_num)
        
        for name, lines in seen.items():
            if len(lines) > 1:
                self.findings['toxic_ai'].append({
                    'type': 'duplicate_function',
                    'severity': 'medium',
                    'title': f'Fonction potentiellement dupliquée: {name}',
                    'file': filepath,
                    'line': lines[0],
                    'evidence': f'Fonction "{name}" définie aux lignes {", ".join(map(str, lines))}',
                    'remediation': 'Consolidez les fonctions dupliquées en une seule implémentation'
                })
    
    def _detect_inconsistent_logic(self, content, filepath):
        patterns = [
            (r'if\s+\w+\s*==\s*None.*if\s+\w+\s*is\s+None', 'Comparaison None incohérente (== vs is)', 'low'),
            (r'return\s+True.*return\s+False.*return\s+True', 'Logique de retour potentiellement incohérente', 'low'),
            (r'except\s*:\s*\n\s*raise', 'Catch-and-rethrow inutile', 'low'),
        ]
        
        for pattern, description, severity in patterns:
            if re.search(pattern, content, re.DOTALL | re.IGNORECASE):
                self.findings['toxic_ai'].append({
                    'type': 'inconsistent_logic',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': 0,
                    'evidence': 'Pattern de logique incohérente détecté',
                    'remediation': 'Revoyez la logique pour plus de cohérence'
                })
    
    def _scan_performance_issues(self, content, filepath):
        for pattern, description, severity in self.PERFORMANCE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.findings['performance'].append({
                    'type': 'performance_issue',
                    'severity': severity,
                    'title': description,
                    'file': filepath,
                    'line': line_num,
                    'evidence': match.group(0)[:100],
                    'remediation': 'Optimisez ce pattern de code pour de meilleures performances'
                })
    
    def _analyze_code_quality(self, content, filepath, ext):
        lines = content.split('\n')
        
        long_lines = sum(1 for line in lines if len(line) > 120)
        if long_lines > 5:
            self.findings['code_quality'].append({
                'type': 'long_lines',
                'severity': 'info',
                'title': f'{long_lines} lignes dépassent 120 caractères',
                'file': filepath,
                'line': 0,
                'evidence': f'{long_lines} lignes trop longues',
                'remediation': 'Divisez les lignes longues pour améliorer la lisibilité'
            })
        
        if len(lines) > 500:
            self.findings['code_quality'].append({
                'type': 'large_file',
                'severity': 'low',
                'title': f'Fichier volumineux ({len(lines)} lignes)',
                'file': filepath,
                'line': 0,
                'evidence': f'{len(lines)} lignes de code',
                'remediation': 'Envisagez de diviser ce fichier en modules plus petits'
            })
        
        placeholders = [
            (r'lorem\s+ipsum', 'Texte Lorem Ipsum'),
            (r'placeholder', 'Placeholder'),
            (r'TODO:\s*replace', 'TODO: replace'),
            (r'test@test\.com', 'Email de test'),
            (r'example@example\.com', 'Email example'),
            (r'["\']password123["\']', 'Mot de passe trivial'),
            (r'["\']admin123["\']', 'Mot de passe admin trivial'),
            (r'["\']changeme["\']', 'Valeur à changer'),
            (r'["\']your[_-]?api[_-]?key["\']', 'Placeholder API key'),
        ]
        
        for pattern, desc in placeholders:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                line_num = content[:matches[0].start()].count('\n') + 1
                self.findings['code_quality'].append({
                    'type': 'placeholder',
                    'severity': 'low',
                    'title': f'{desc} détecté',
                    'file': filepath,
                    'line': line_num,
                    'evidence': matches[0].group(0),
                    'remediation': 'Remplacez les placeholders par des valeurs réelles ou des variables d\'environnement'
                })
    
    def _analyze_git_history(self):
        if not self.temp_dir:
            return
        try:
            result = subprocess.run(
                ['git', 'log', '--oneline', '-n', '100'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            commits = result.stdout.strip().split('\n') if result.stdout else []
            
            if len(commits) < 10:
                self.findings['git_hygiene'].append({
                    'type': 'sparse_history',
                    'severity': 'info',
                    'title': 'Historique Git limité',
                    'file': '.git',
                    'line': 0,
                    'evidence': f'{len(commits)} commits analysés',
                    'remediation': 'Maintenez un historique de commits régulier et descriptif'
                })
            
            poor_messages = [c for c in commits if re.search(
                r'^[a-f0-9]+\s+(wip|work in progress|temp|test|fix|update|changes|stuff|asdf|qwer|commit|\.+)$', 
                c, re.I
            )]
            if len(poor_messages) > len(commits) * 0.25:
                self.findings['git_hygiene'].append({
                    'type': 'poor_commit_messages',
                    'severity': 'low',
                    'title': 'Messages de commit peu descriptifs',
                    'file': '.git',
                    'line': 0,
                    'evidence': f'{len(poor_messages)}/{len(commits)} commits avec messages vagues',
                    'remediation': 'Utilisez des messages de commit conventionnels (feat:, fix:, docs:, etc.)'
                })
            
            result = subprocess.run(
                ['git', 'log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            added_files = [f for f in result.stdout.split('\n') if f.strip()] if result.stdout else []
            
            for sensitive in self.SENSITIVE_FILES_GIT:
                for f in added_files:
                    if sensitive.startswith('*'):
                        if f.endswith(sensitive[1:]):
                            self.findings['git_hygiene'].append({
                                'type': 'sensitive_in_history',
                                'severity': 'high',
                                'title': f'Fichier sensible dans l\'historique: {f}',
                                'file': f,
                                'line': 0,
                                'evidence': 'Ce type de fichier ne devrait jamais être commité',
                                'remediation': 'Utilisez git-filter-branch ou BFG Repo-Cleaner pour nettoyer l\'historique, puis changez les credentials exposés'
                            })
                    elif sensitive in f:
                        severity = 'critical' if any(x in f for x in ['.env', 'credential', 'secret', 'key']) else 'high'
                        self.findings['git_hygiene'].append({
                            'type': 'sensitive_in_history',
                            'severity': severity,
                            'title': f'Fichier sensible dans l\'historique: {f}',
                            'file': f,
                            'line': 0,
                            'evidence': 'Fichier potentiellement sensible ajouté dans l\'historique Git',
                            'remediation': 'Utilisez git-filter-branch ou BFG Repo-Cleaner pour nettoyer l\'historique, puis changez tous les secrets exposés'
                        })
            
            result = subprocess.run(
                ['git', 'branch', '-a'],
                cwd=self.temp_dir,
                capture_output=True,
                text=True
            )
            branches = [b.strip() for b in result.stdout.split('\n') if b.strip()] if result.stdout else []
            stale_branches = [b for b in branches if any(x in b.lower() for x in ['temp', 'old', 'backup', 'test', 'wip'])]
            if len(stale_branches) > 3:
                self.findings['git_hygiene'].append({
                    'type': 'stale_branches',
                    'severity': 'info',
                    'title': f'{len(stale_branches)} branches potentiellement obsolètes',
                    'file': '.git',
                    'line': 0,
                    'evidence': ', '.join(stale_branches[:5]),
                    'remediation': 'Nettoyez les branches obsolètes pour garder le dépôt propre'
                })
            
        except Exception as e:
            pass
    
    def _analyze_dependencies(self):
        if not self.temp_dir:
            return
        dep_files = {
            'requirements.txt': self._analyze_python_deps,
            'Pipfile': self._analyze_pipfile,
            'pyproject.toml': self._analyze_pyproject,
            'package.json': self._analyze_npm_deps,
            'Gemfile': self._analyze_ruby_deps,
            'go.mod': self._analyze_go_deps,
            'Cargo.toml': self._analyze_rust_deps,
            'pom.xml': self._analyze_maven_deps,
            'composer.json': self._analyze_php_deps,
        }
        
        found_dep_files = []
        for filename, analyzer in dep_files.items():
            filepath = os.path.join(self.temp_dir, filename)
            if os.path.exists(filepath):
                found_dep_files.append(filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                        analyzer(content, filename)
                except:
                    pass
        
        lockfiles = {
            'package.json': ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
            'requirements.txt': ['requirements.lock', 'Pipfile.lock', 'poetry.lock'],
            'Gemfile': ['Gemfile.lock'],
            'go.mod': ['go.sum'],
            'Cargo.toml': ['Cargo.lock'],
            'composer.json': ['composer.lock'],
        }
        
        for main_file, locks in lockfiles.items():
            if os.path.exists(os.path.join(self.temp_dir, main_file)):
                has_lock = any(os.path.exists(os.path.join(self.temp_dir, lf)) for lf in locks)
                if not has_lock:
                    self.findings['dependencies'].append({
                        'type': 'no_lockfile',
                        'severity': 'medium',
                        'title': f'Fichier de verrouillage manquant pour {main_file}',
                        'file': main_file,
                        'line': 0,
                        'evidence': f'Lockfiles attendus: {", ".join(locks)}',
                        'remediation': 'Générez un fichier de verrouillage pour des builds reproductibles et sécurisés'
                    })
    
    def _analyze_python_deps(self, content, filename):
        lines = content.strip().split('\n')
        deps = {}
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:\[.*\])?(?:([=<>!~]+)(.+))?', line)
            if match:
                pkg_name = match.group(1).lower()
                version_op = match.group(2)
                version = match.group(3)
                
                if not version_op:
                    self.findings['dependencies'].append({
                        'type': 'unpinned_dependency',
                        'severity': 'low',
                        'title': f'Dépendance non verrouillée: {pkg_name}',
                        'file': filename,
                        'line': 0,
                        'evidence': line,
                        'remediation': 'Épinglez la version exacte pour des builds reproductibles'
                    })
                
                if pkg_name in self.VULNERABLE_PACKAGES.get('python', {}):
                    vuln_info = self.VULNERABLE_PACKAGES['python'][pkg_name]
                    self.findings['dependencies'].append({
                        'type': 'vulnerable_dependency',
                        'severity': vuln_info['severity'],
                        'title': f'Dépendance potentiellement vulnérable: {pkg_name}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg_name} - {vuln_info["cve"]}',
                        'cve': vuln_info['cve'],
                        'remediation': f'Mettez à jour {pkg_name} vers une version non vulnérable'
                    })
    
    def _analyze_pipfile(self, content, filename):
        pass
    
    def _analyze_pyproject(self, content, filename):
        pass
    
    def _analyze_npm_deps(self, content, filename):
        try:
            data = json.loads(content)
            all_deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            
            for pkg, version in all_deps.items():
                if version in ['*', 'latest']:
                    self.findings['dependencies'].append({
                        'type': 'dangerous_version',
                        'severity': 'high',
                        'title': f'Version dangereuse: {pkg}@{version}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg}: {version}',
                        'remediation': 'N\'utilisez jamais * ou latest en production'
                    })
                elif version.startswith('^') or version.startswith('~'):
                    pass
                
                pkg_lower = pkg.lower()
                if pkg_lower in self.VULNERABLE_PACKAGES.get('npm', {}):
                    vuln_info = self.VULNERABLE_PACKAGES['npm'][pkg_lower]
                    self.findings['dependencies'].append({
                        'type': 'vulnerable_dependency',
                        'severity': vuln_info['severity'],
                        'title': f'Dépendance potentiellement vulnérable: {pkg}',
                        'file': filename,
                        'line': 0,
                        'evidence': f'{pkg}@{version} - {vuln_info["cve"]}',
                        'cve': vuln_info['cve'],
                        'remediation': f'Mettez à jour {pkg} vers une version non vulnérable'
                    })
            
            if 'engines' not in data:
                self.findings['dependencies'].append({
                    'type': 'missing_engines',
                    'severity': 'low',
                    'title': 'Version Node.js non spécifiée',
                    'file': filename,
                    'line': 0,
                    'evidence': 'Champ "engines" manquant',
                    'remediation': 'Spécifiez la version Node.js requise dans le champ "engines"'
                })
                
        except json.JSONDecodeError:
            self.findings['dependencies'].append({
                'type': 'invalid_package_json',
                'severity': 'high',
                'title': 'package.json invalide',
                'file': filename,
                'line': 0,
                'evidence': 'Erreur de parsing JSON',
                'remediation': 'Corrigez la syntaxe du fichier package.json'
            })
    
    def _analyze_ruby_deps(self, content, filename):
        pass
    
    def _analyze_go_deps(self, content, filename):
        pass
    
    def _analyze_rust_deps(self, content, filename):
        pass
    
    def _analyze_maven_deps(self, content, filename):
        pass
    
    def _analyze_php_deps(self, content, filename):
        pass
    
    def _analyze_architecture(self):
        if not self.temp_dir:
            return
        structure = defaultdict(list)
        
        for root, dirs, files in os.walk(self.temp_dir):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv'}]
            
            relative_root = os.path.relpath(root, self.temp_dir)
            if relative_root == '.':
                relative_root = ''
            
            for f in files:
                if relative_root:
                    structure[relative_root].append(f)
                else:
                    structure['root'].append(f)
        
        root_code_files = [f for f in structure.get('root', []) 
                         if any(f.endswith(ext) for ext in self.LANGUAGE_EXTENSIONS.keys())]
        
        if len(root_code_files) > 15:
            self.findings['architecture'].append({
                'type': 'flat_structure',
                'severity': 'medium',
                'title': 'Structure de fichiers trop plate',
                'file': '/',
                'line': 0,
                'evidence': f'{len(root_code_files)} fichiers de code à la racine',
                'remediation': 'Organisez le code en modules/packages avec une structure claire (src/, lib/, etc.)'
            })
        
        common_dirs = ['src', 'lib', 'app', 'pkg', 'internal', 'cmd']
        has_source_structure = any(d in structure for d in common_dirs)
        
        test_dirs = ['tests', 'test', 'spec', '__tests__', 'test_*']
        has_tests = any(d in structure or any(d.startswith('test') for d in structure) for d in test_dirs)
        
        test_files = []
        for root, dirs, files in os.walk(self.temp_dir):
            for f in files:
                if re.search(r'(test_|_test|\.test\.|\.spec\.)', f, re.I):
                    test_files.append(f)
        
        if not has_tests and not test_files and self.stats['total_files'] > 10:
            self.findings['architecture'].append({
                'type': 'no_tests',
                'severity': 'high',
                'title': 'Aucun test détecté',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de dossier tests/ ni de fichiers *test*',
                'remediation': 'Ajoutez des tests unitaires et d\'intégration pour assurer la qualité du code'
            })
        elif test_files and len(test_files) < self.stats['total_files'] * 0.1:
            self.findings['architecture'].append({
                'type': 'insufficient_tests',
                'severity': 'medium',
                'title': 'Couverture de tests potentiellement insuffisante',
                'file': '/',
                'line': 0,
                'evidence': f'{len(test_files)} fichiers de test pour {self.stats["total_files"]} fichiers',
                'remediation': 'Augmentez la couverture de tests (objectif: >80%)'
            })
        
        ci_files = ['.github/workflows', '.gitlab-ci.yml', '.travis.yml', 'Jenkinsfile', '.circleci', 'azure-pipelines.yml']
        has_ci = any(
            os.path.exists(os.path.join(self.temp_dir, cf)) or 
            any(cf in s for s in structure.keys())
            for cf in ci_files
        )
        
        if not has_ci and self.stats['total_files'] > 20:
            self.findings['architecture'].append({
                'type': 'no_ci',
                'severity': 'low',
                'title': 'Aucune configuration CI/CD détectée',
                'file': '/',
                'line': 0,
                'evidence': 'Pas de fichier de configuration CI trouvé',
                'remediation': 'Ajoutez une pipeline CI/CD (GitHub Actions, GitLab CI, etc.)'
            })
        
        config_dirs = ['config', 'configs', 'settings']
        env_example = ['.env.example', '.env.sample', 'env.example']
        has_env_example = any(os.path.exists(os.path.join(self.temp_dir, ef)) for ef in env_example)
        
        if os.path.exists(os.path.join(self.temp_dir, '.env')) and not has_env_example:
            self.findings['architecture'].append({
                'type': 'missing_env_example',
                'severity': 'low',
                'title': '.env.example manquant',
                'file': '/',
                'line': 0,
                'evidence': '.env existe mais pas de template .env.example',
                'remediation': 'Créez un fichier .env.example avec les variables requises (sans valeurs sensibles)'
            })
    
    def _analyze_documentation(self):
        if not self.temp_dir:
            return
        readme_path = None
        for name in ['README.md', 'README.rst', 'README.txt', 'README', 'readme.md']:
            path = os.path.join(self.temp_dir, name)
            if os.path.exists(path):
                readme_path = path
                break
        
        if not readme_path:
            self.findings['documentation'].append({
                'type': 'no_readme',
                'severity': 'high',
                'title': 'README manquant',
                'file': '/',
                'line': 0,
                'evidence': 'Aucun fichier README trouvé',
                'remediation': 'Créez un README.md avec description, installation, utilisation et contribution'
            })
        else:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                readme_content = f.read()
                readme_lower = readme_content.lower()
                
                required_sections = [
                    ('installation', 'Section Installation manquante'),
                    ('usage', 'Section Usage/Utilisation manquante'),
                ]
                
                recommended_sections = [
                    ('license', 'Information de licence manquante'),
                    ('contributing', 'Guide de contribution manquant'),
                    ('api', 'Documentation API manquante'),
                ]
                
                for keyword, message in required_sections:
                    if keyword not in readme_lower:
                        self.findings['documentation'].append({
                            'type': 'incomplete_readme',
                            'severity': 'medium',
                            'title': message,
                            'file': os.path.basename(readme_path),
                            'line': 0,
                            'evidence': f'Section "{keyword}" non trouvée',
                            'remediation': f'Ajoutez une section {keyword.title()} détaillée'
                        })
                
                for keyword, message in recommended_sections:
                    if keyword not in readme_lower:
                        self.findings['documentation'].append({
                            'type': 'missing_section',
                            'severity': 'low',
                            'title': message,
                            'file': os.path.basename(readme_path),
                            'line': 0,
                            'evidence': f'Section "{keyword}" recommandée mais non trouvée',
                            'remediation': f'Envisagez d\'ajouter une section {keyword.title()}'
                        })
                
                if len(readme_content) < 300:
                    self.findings['documentation'].append({
                        'type': 'short_readme',
                        'severity': 'medium',
                        'title': 'README trop court',
                        'file': os.path.basename(readme_path),
                        'line': 0,
                        'evidence': f'{len(readme_content)} caractères seulement',
                        'remediation': 'Étoffez la documentation avec plus de détails sur le projet'
                    })
        
        gitignore_path = os.path.join(self.temp_dir, '.gitignore')
        if not os.path.exists(gitignore_path):
            self.findings['documentation'].append({
                'type': 'no_gitignore',
                'severity': 'medium',
                'title': '.gitignore manquant',
                'file': '/',
                'line': 0,
                'evidence': 'Fichier .gitignore non trouvé',
                'remediation': 'Créez un .gitignore adapté à votre stack (utilisez gitignore.io)'
            })
        else:
            with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
                gitignore_content = f.read().lower()
                
                critical_ignores = [
                    ('.env', 'Fichiers .env non ignorés'),
                    ('node_modules', 'node_modules non ignoré'),
                    ('__pycache__', '__pycache__ non ignoré'),
                    ('.pyc', 'Fichiers .pyc non ignorés'),
                ]
                
                for pattern, message in critical_ignores:
                    if pattern not in gitignore_content:
                        if (pattern == 'node_modules' and 'JavaScript' in self.stats['languages']) or \
                           (pattern in ['.pyc', '__pycache__'] and 'Python' in self.stats['languages']) or \
                           pattern == '.env':
                            self.findings['documentation'].append({
                                'type': 'incomplete_gitignore',
                                'severity': 'medium' if pattern == '.env' else 'low',
                                'title': message,
                                'file': '.gitignore',
                                'line': 0,
                                'evidence': f'Pattern "{pattern}" non trouvé',
                                'remediation': f'Ajoutez {pattern} au .gitignore'
                            })
    
    def _calculate_scores(self):
        def category_score(findings_list, max_penalty=100):
            if not findings_list:
                return 100
            
            total_penalty = 0
            for finding in findings_list:
                severity = finding.get('severity', 'info')
                total_penalty += self.SEVERITY_SCORES.get(severity, 0)
            
            normalized = min(total_penalty, max_penalty)
            return max(0, 100 - normalized)
        
        security_score = category_score(self.findings['security'], max_penalty=100)
        deps_score = category_score(self.findings['dependencies'], max_penalty=60)
        arch_score = category_score(self.findings['architecture'], max_penalty=50)
        perf_score = category_score(self.findings['performance'], max_penalty=50)
        git_score = category_score(self.findings['git_hygiene'], max_penalty=40)
        doc_score = category_score(self.findings['documentation'], max_penalty=40)
        toxic_score = category_score(self.findings['toxic_ai'], max_penalty=50)
        
        overall_score = (
            security_score * self.SECURITY_WEIGHT +
            deps_score * self.DEPENDENCIES_WEIGHT +
            arch_score * self.ARCHITECTURE_WEIGHT +
            toxic_score * self.TOXIC_AI_WEIGHT +
            perf_score * self.PERFORMANCE_WEIGHT +
            git_score * self.GIT_QUALITY_WEIGHT +
            doc_score * self.DOCUMENTATION_WEIGHT
        )
        
        if overall_score >= 85:
            risk_level = 'low'
        elif overall_score >= 70:
            risk_level = 'medium'
        elif overall_score >= 50:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        return {
            'overall': round(overall_score, 1),
            'security': round(security_score, 1),
            'dependencies': round(deps_score, 1),
            'architecture': round(arch_score, 1),
            'performance': round(perf_score, 1),
            'documentation': round(doc_score, 1),
            'risk_level': risk_level
        }
    
    def _count_by_severity(self, severity):
        count = 0
        for category in self.findings.values():
            for finding in category:
                if finding.get('severity') == severity:
                    count += 1
        return count
    
    def _redact_secret(self, secret):
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _generate_summary(self, scores):
        summary_parts = []
        
        total_issues = sum(len(f) for f in self.findings.values())
        critical = self._count_by_severity('critical')
        high = self._count_by_severity('high')
        
        if scores['risk_level'] == 'critical':
            summary_parts.append(f"⚠️ RISQUE CRITIQUE: {total_issues} problèmes détectés dont {critical} critiques et {high} élevés nécessitant une action immédiate.")
        elif scores['risk_level'] == 'high':
            summary_parts.append(f"⚠️ RISQUE ÉLEVÉ: {total_issues} problèmes détectés nécessitant une attention prioritaire.")
        elif scores['risk_level'] == 'medium':
            summary_parts.append(f"⚡ RISQUE MODÉRÉ: {total_issues} problèmes détectés, des améliorations sont recommandées.")
        else:
            summary_parts.append(f"✅ RISQUE FAIBLE: Le code semble bien sécurisé avec {total_issues} points d'attention mineurs.")
        
        if self.findings['security']:
            sec_critical = sum(1 for f in self.findings['security'] if f.get('severity') == 'critical')
            sec_high = sum(1 for f in self.findings['security'] if f.get('severity') == 'high')
            summary_parts.append(f"🔒 Sécurité: {len(self.findings['security'])} vulnérabilités ({sec_critical} critiques, {sec_high} élevées).")
        
        if self.stats['detected_frameworks']:
            summary_parts.append(f"🛠️ Frameworks: {', '.join(sorted(self.stats['detected_frameworks']))}")
        
        primary_lang = self._get_primary_language()
        if primary_lang != 'Unknown':
            other_langs = [l for l in self.stats['languages'].keys() if l != primary_lang][:2]
            lang_str = primary_lang
            if other_langs:
                lang_str += f" (+ {', '.join(other_langs)})"
            summary_parts.append(f"📝 Langage principal: {lang_str}")
        
        return ' '.join(summary_parts)
    
    def _generate_security_summary(self):
        if not self.findings['security']:
            return {'status': 'clean', 'message': 'Aucune vulnérabilité de sécurité détectée'}
        
        categories = defaultdict(list)
        for finding in self.findings['security']:
            cat = finding.get('category', 'Autre')
            categories[cat].append(finding)
        
        summary = {
            'status': 'issues_found',
            'total_vulnerabilities': len(self.findings['security']),
            'critical_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'critical'),
            'high_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'high'),
            'medium_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'medium'),
            'low_count': sum(1 for f in self.findings['security'] if f.get('severity') == 'low'),
            'categories': {cat: len(findings) for cat, findings in categories.items()},
            'owasp_coverage': list(set(f.get('owasp', '') for f in self.findings['security'] if f.get('owasp')))
        }
        
        return summary
    
    def _generate_recommendations(self):
        recommendations = []
        
        critical_findings = [f for f in self.findings['security'] if f.get('severity') == 'critical']
        if critical_findings:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Corriger les vulnérabilités critiques',
                'description': f'{len(critical_findings)} vulnérabilités critiques nécessitent une correction immédiate',
                'items': [f['title'] for f in critical_findings[:5]]
            })
        
        secret_findings = [f for f in self.findings['security'] if f.get('type') == 'secret_exposed']
        if secret_findings:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Supprimer les secrets exposés',
                'description': 'Supprimez tous les secrets du code et utilisez des variables d\'environnement',
                'items': [f['title'] for f in secret_findings[:3]]
            })
        
        if not any('tests' in str(f) for f in self.findings['architecture']):
            pass
        
        no_tests = [f for f in self.findings['architecture'] if 'test' in f.get('type', '').lower()]
        if no_tests:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Ajouter des tests',
                'description': 'La couverture de tests est insuffisante',
                'items': ['Ajoutez des tests unitaires', 'Ajoutez des tests d\'intégration', 'Configurez une pipeline CI']
            })
        
        if self.findings['dependencies']:
            vuln_deps = [f for f in self.findings['dependencies'] if f.get('type') == 'vulnerable_dependency']
            if vuln_deps:
                recommendations.append({
                    'priority': 'HIGH',
                    'title': 'Mettre à jour les dépendances vulnérables',
                    'description': f'{len(vuln_deps)} dépendances avec des vulnérabilités connues',
                    'items': [f['title'] for f in vuln_deps[:5]]
                })
        
        return recommendations
    
    def _cleanup(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass
