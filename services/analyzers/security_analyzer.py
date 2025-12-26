"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Analyseur de vulnerabilites de securite OWASP.
"""

from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class SecurityAnalyzer(BaseAnalyzer):
    
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'API Key exposée', 'critical', "Stocker les clés API dans des variables d'environnement"),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', 'Secret Key exposée', 'critical', "Utiliser un gestionnaire de secrets"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', 'Mot de passe hardcodé', 'critical', "Ne jamais stocker de mots de passe dans le code"),
        (r'(?i)(token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', 'Token exposé', 'critical', "Utiliser des variables d'environnement"),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?', 'AWS Access Key exposée', 'critical', "Utiliser AWS IAM roles ou variables d'environnement"),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', 'AWS Secret Key exposée', 'critical', "Utiliser AWS IAM roles"),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID détectée', 'critical', "Révoquer immédiatement et utiliser IAM roles"),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token exposé', 'critical', "Révoquer et utiliser des secrets GitHub Actions"),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GitHub Fine-grained PAT exposé', 'critical', "Révoquer immédiatement"),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token exposé', 'critical', "Révoquer le token OAuth"),
        (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key exposée', 'critical', "Révoquer et stocker dans les variables d'environnement"),
        (r'sk-proj-[a-zA-Z0-9\-_]{80,}', 'OpenAI Project API Key exposée', 'critical', "Révoquer la clé projet OpenAI"),
        (r'sk-ant-[a-zA-Z0-9\-_]{80,}', 'Anthropic API Key exposée', 'critical', "Révoquer la clé Anthropic"),
        (r'xox[baprs]-[a-zA-Z0-9\-]{10,}', 'Slack Token exposé', 'critical', "Révoquer le token Slack"),
        (r'(?i)(mongodb(\+srv)?://[^"\'\s]+)', 'MongoDB Connection String exposée', 'critical', "Utiliser des variables d'environnement pour DATABASE_URL"),
        (r'(?i)(postgres(ql)?://[^"\'\s]+)', 'PostgreSQL Connection String exposée', 'critical', "Utiliser DATABASE_URL en variable d'environnement"),
        (r'(?i)(mysql://[^"\'\s]+)', 'MySQL Connection String exposée', 'critical', "Utiliser DATABASE_URL en variable d'environnement"),
        (r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Clé privée exposée', 'critical', "Ne jamais commiter de clés privées"),
        (r'(?i)(stripe[_-]?secret[_-]?key|sk_live_)[a-zA-Z0-9]{20,}', 'Stripe Secret Key exposée', 'critical', "Utiliser des variables d'environnement Stripe"),
        (r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}', 'SendGrid API Key exposée', 'critical', "Révoquer et utiliser des variables d'environnement"),
    ]
    
    SQL_INJECTION_PATTERNS = [
        (r'execute\s*\(\s*["\'].*%s.*["\']', 'Injection SQL potentielle via string formatting', 'critical', "Utiliser des requêtes paramétrées: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
        (r'execute\s*\(\s*f["\']', 'Injection SQL via f-string', 'critical', "Ne jamais utiliser f-strings pour les requêtes SQL"),
        (r'execute\s*\(\s*["\'].*\+\s*\w+', 'Injection SQL via concaténation', 'critical', "Utiliser des paramètres préparés au lieu de concaténer"),
        (r'cursor\.execute\s*\([^,]+\+', 'Injection SQL via concaténation cursor', 'critical', "Utiliser cursor.execute(query, params) avec des placeholders"),
        (r'\.raw\s*\(\s*["\'].*%s', 'Raw SQL avec interpolation non sécurisée', 'high', "Utiliser les paramètres raw() avec des placeholders"),
        (r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+\s*\w+', 'SQL dynamique avec concaténation', 'critical', "Utiliser un ORM ou des requêtes préparées"),
        (r'\.query\s*\(\s*`[^`]*\$\{', 'Template literal SQL injection (Node.js)', 'critical', "Utiliser des paramètres avec pool.query(sql, [params])"),
        (r'db\.query\s*\(\s*["\'].*\+', 'DB query avec concaténation', 'critical', "Utiliser des requêtes paramétrées"),
        (r'sequelize\.query\s*\(\s*["\'].*\+', 'Sequelize raw query injection', 'critical', "Utiliser sequelize.query avec replacements"),
        (r'knex\.raw\s*\(\s*["\'].*\+', 'Knex raw query injection', 'critical', "Utiliser knex.raw avec des bindings"),
    ]
    
    XSS_PATTERNS = [
        (r'innerHTML\s*=\s*[^"\']*\+', 'XSS via innerHTML avec concaténation', 'high', "Utiliser textContent ou échapper le contenu"),
        (r'innerHTML\s*=\s*[^;]*request', 'XSS via innerHTML avec user input', 'critical', "Ne jamais injecter d'entrée utilisateur dans innerHTML"),
        (r'document\.write\s*\([^)]*\+', 'XSS via document.write', 'high', "Éviter document.write, utiliser DOM manipulation"),
        (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML utilisé', 'medium', "Éviter dangerouslySetInnerHTML, utiliser des bibliothèques de sanitization"),
        (r'\|\s*safe\s*}}', 'Django/Jinja2 safe filter - XSS potentiel', 'medium', "Vérifier que le contenu est sûr avant d'utiliser |safe"),
        (r'Markup\s*\(', 'Flask Markup sans échappement', 'medium', "S'assurer que le contenu passé à Markup est échappé"),
        (r'v-html\s*=', 'Vue v-html directive - XSS potentiel', 'medium', "Sanitizer le contenu avant v-html ou utiliser v-text"),
        (r'\[innerHTML\]\s*=', 'Angular innerHTML binding', 'medium', "Utiliser DomSanitizer pour valider le contenu"),
        (r'eval\s*\([^)]*\+', 'Eval avec concaténation', 'critical', "Ne jamais utiliser eval() avec des entrées dynamiques"),
        (r'eval\s*\([^)]*request', 'Eval avec user input', 'critical', "Supprimer complètement eval() avec entrées utilisateur"),
        (r'Function\s*\([^)]*\+', 'Function constructor avec input', 'critical', "Éviter le constructeur Function dynamique"),
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        (r'os\.system\s*\([^)]*\+', 'Command injection via os.system', 'critical', "Utiliser subprocess avec une liste d'arguments"),
        (r'os\.system\s*\([^)]*request', 'Command injection via os.system avec user input', 'critical', "Ne jamais passer d'entrée utilisateur à os.system"),
        (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'Subprocess avec shell=True', 'critical', "Utiliser shell=False et passer les arguments en liste"),
        (r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True', 'Popen avec shell=True', 'critical', "Utiliser shell=False avec liste d'arguments"),
        (r'subprocess\.run\s*\([^)]*shell\s*=\s*True', 'subprocess.run avec shell=True', 'critical', "Utiliser subprocess.run(['cmd', 'arg1', 'arg2'])"),
        (r'exec\s*\([^)]*\+', 'Exec avec concaténation', 'critical', "Éviter exec() avec des entrées dynamiques"),
        (r'child_process\.exec\s*\([^)]*\+', 'Node exec avec concaténation', 'critical', "Utiliser child_process.spawn avec arguments séparés"),
        (r'shell_exec\s*\(', 'PHP shell_exec', 'critical', "Utiliser escapeshellarg() et escapeshellcmd()"),
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        (r'open\s*\([^)]*\+', 'Path traversal potentiel via open()', 'high', "Valider le chemin avec os.path.basename() ou pathlib"),
        (r'open\s*\([^)]*request\.', 'Path traversal via user input', 'critical', "Ne jamais utiliser d'entrée utilisateur directement dans open()"),
        (r'os\.path\.join\s*\([^)]*request\.', 'Path traversal via user input', 'critical', "Valider le chemin final est dans le répertoire autorisé"),
        (r'send_file\s*\([^)]*\+', 'Path traversal via send_file', 'high', "Utiliser send_from_directory avec un répertoire sûr"),
        (r'\.\./', 'Path traversal pattern détecté', 'medium', "Filtrer et valider les chemins de fichiers"),
        (r'readFile\s*\([^)]*\+', 'Node readFile avec concaténation', 'high', "Valider les chemins avant lecture"),
        (r'require\s*\([^)]*\+', 'Dynamic require (LFI potentiel)', 'high', "Éviter require() dynamique"),
    ]
    
    INSECURE_DESERIALIZATION_PATTERNS = [
        (r'pickle\.loads?\s*\(', 'Désérialisation pickle non sécurisée', 'critical', "Éviter pickle, utiliser JSON ou messagepack"),
        (r'pickle\.Unpickler\s*\(', 'Pickle Unpickler non sécurisé', 'critical', "Ne jamais unpickle de données non fiables"),
        (r'yaml\.load\s*\([^)]*\)(?!.*SafeLoader)', 'YAML load sans SafeLoader', 'high', "Utiliser yaml.safe_load() ou yaml.load(data, Loader=yaml.SafeLoader)"),
        (r'yaml\.unsafe_load\s*\(', 'YAML unsafe_load', 'critical', "Remplacer par yaml.safe_load()"),
        (r'marshal\.loads?\s*\(', 'Désérialisation marshal', 'high', "Éviter marshal pour données non fiables"),
        (r'unserialize\s*\(', 'PHP unserialize non sécurisé', 'critical', "Utiliser json_decode() au lieu de unserialize()"),
    ]
    
    INSECURE_CONFIG_PATTERNS = [
        (r'DEBUG\s*=\s*True', 'Mode DEBUG activé', 'high', "Désactiver DEBUG en production: DEBUG = False"),
        (r'FLASK_DEBUG\s*=\s*1', 'Flask DEBUG mode', 'high', "Définir FLASK_DEBUG=0 en production"),
        (r'verify\s*=\s*False', 'SSL verification désactivée', 'critical', "Activer la vérification SSL: verify=True"),
        (r'ssl\s*=\s*False', 'SSL désactivé', 'critical', "Activer SSL pour les connexions sécurisées"),
        (r'CORS\s*\(\s*\w+\s*,\s*resources\s*=.*\*', 'CORS trop permissif', 'medium', "Spécifier les origines autorisées explicitement"),
        (r'Access-Control-Allow-Origin.*\*', 'CORS wildcard', 'medium', "Définir des origines CORS spécifiques"),
        (r'SECRET_KEY\s*=\s*["\'][^"\']{1,20}["\']', 'Secret key trop courte', 'high', "Utiliser une clé secrète d'au moins 32 caractères"),
        (r'SECRET_KEY\s*=\s*["\']changeme', 'Secret key par défaut', 'critical', "Générer une nouvelle SECRET_KEY aléatoire"),
        (r'WTF_CSRF_ENABLED\s*=\s*False', 'Flask-WTF CSRF désactivé', 'critical', "Activer la protection CSRF"),
        (r'SESSION_COOKIE_SECURE\s*=\s*False', 'Session cookie non sécurisé', 'high', "Activer SESSION_COOKIE_SECURE en production"),
    ]
    
    SSRF_PATTERNS = [
        (r'requests\.get\s*\([^)]*request\.', 'SSRF potentiel via requests', 'critical', "Valider et filtrer les URLs avant les requêtes"),
        (r'requests\.post\s*\([^)]*request\.', 'SSRF potentiel via requests.post', 'critical', "Utiliser une allowlist d'URLs autorisées"),
        (r'urllib\.request\.urlopen\s*\([^)]*\+', 'SSRF via urllib', 'critical', "Valider les URLs contre une liste blanche"),
        (r'fetch\s*\([^)]*request\.', 'SSRF via fetch avec user input', 'critical', "Ne jamais fetch d'URLs fournies par l'utilisateur"),
        (r'axios\s*\.\w+\s*\([^)]*request\.', 'SSRF via axios avec user input', 'critical', "Valider les URLs avant les requêtes axios"),
    ]
    
    AUTH_PATTERNS = [
        (r'password\s*==\s*', 'Comparaison de mot de passe non sécurisée', 'critical', "Utiliser bcrypt.checkpw() ou argon2"),
        (r'if\s+password\s*==', 'Comparaison directe de mot de passe', 'critical', "Utiliser des fonctions de comparaison sécurisées timing-safe"),
        (r'md5\s*\(.*password', 'MD5 pour hachage de mot de passe', 'critical', "Utiliser bcrypt, argon2 ou scrypt"),
        (r'sha1\s*\(.*password', 'SHA1 pour hachage de mot de passe', 'high', "Utiliser bcrypt, argon2 ou scrypt"),
        (r'hashlib\.md5\s*\(', 'MD5 (obsolète pour sécurité)', 'high', "Utiliser SHA-256 minimum ou bcrypt pour mots de passe"),
        (r'jwt\.decode\s*\([^)]*verify\s*=\s*False', 'JWT decode sans vérification', 'critical', "Toujours vérifier la signature JWT"),
        (r'algorithm\s*[=:]\s*["\']?none', 'JWT algorithm none', 'critical', "Spécifier un algorithme JWT sécurisé (RS256, ES256)"),
    ]
    
    HARDCODED_VALUES_PATTERNS = [
        (r'admin["\']?\s*:\s*["\']admin', 'Credentials admin par défaut', 'critical', "Supprimer les credentials par défaut"),
        (r'root["\']?\s*:\s*["\']root', 'Credentials root par défaut', 'critical', "Supprimer les credentials par défaut"),
        (r'password\s*=\s*["\']admin', 'Password admin hardcodé', 'critical', "Utiliser des variables d'environnement"),
        (r'password\s*=\s*["\']password', 'Password trivial hardcodé', 'critical', "Utiliser des variables d'environnement"),
        (r'password\s*=\s*["\']123456', 'Password 123456 hardcodé', 'critical', "Supprimer ce mot de passe dangereux"),
    ]
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        self.findings = []
        
        self.findings.extend(self._scan_patterns(content, filepath, self.SECRET_PATTERNS, 'secret'))
        self.findings.extend(self._scan_patterns(content, filepath, self.SQL_INJECTION_PATTERNS, 'sql_injection'))
        self.findings.extend(self._scan_patterns(content, filepath, self.XSS_PATTERNS, 'xss'))
        self.findings.extend(self._scan_patterns(content, filepath, self.COMMAND_INJECTION_PATTERNS, 'command_injection'))
        self.findings.extend(self._scan_patterns(content, filepath, self.PATH_TRAVERSAL_PATTERNS, 'path_traversal'))
        self.findings.extend(self._scan_patterns(content, filepath, self.INSECURE_DESERIALIZATION_PATTERNS, 'deserialization'))
        self.findings.extend(self._scan_patterns(content, filepath, self.INSECURE_CONFIG_PATTERNS, 'config'))
        self.findings.extend(self._scan_patterns(content, filepath, self.SSRF_PATTERNS, 'ssrf'))
        self.findings.extend(self._scan_patterns(content, filepath, self.AUTH_PATTERNS, 'auth'))
        self.findings.extend(self._scan_patterns(content, filepath, self.HARDCODED_VALUES_PATTERNS, 'hardcoded'))
        
        return self.findings
