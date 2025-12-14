from typing import List, Dict, Any
from .base_analyzer import BaseAnalyzer


class PerformanceAnalyzer(BaseAnalyzer):
    
    PERFORMANCE_PATTERNS = [
        (r'while\s+True\s*:', 'Boucle infinie potentielle', 'medium', "Ajouter une condition de sortie claire"),
        (r'while\s*\(\s*true\s*\)', 'Boucle infinie potentielle (JS)', 'medium', "Ajouter un break ou condition de sortie"),
        (r'for\s+\w+\s+in\s+\w+\.objects\.all\(\)', 'Query N+1 potentielle Django', 'high', "Utiliser select_related() ou prefetch_related()"),
        (r'\.objects\.get\s*\([^)]*\).*for', 'N+1 query dans boucle', 'high', "Charger les données en une seule requête avant la boucle"),
        (r'\.objects\.filter.*for.*\.objects\.(get|filter)', 'Nested queries N+1', 'high', "Utiliser prefetch_related() ou restructurer les requêtes"),
        (r'time\.sleep\s*\(\s*\d{2,}\s*\)', 'Sleep long bloquant', 'medium', "Utiliser des tâches asynchrones pour les délais longs"),
        (r'Thread\.sleep\s*\(\s*\d{4,}\s*\)', 'Thread.sleep très long', 'medium', "Utiliser des mécanismes asynchrones"),
        (r'\+\s*=\s*["\']', 'Concaténation string dans boucle', 'low', "Utiliser join() ou StringBuilder"),
        (r'global\s+\w+', 'Variable globale utilisée', 'low', "Éviter les variables globales, utiliser des paramètres"),
        (r'SELECT\s+\*\s+FROM', 'SELECT * non optimisé', 'low', "Spécifier les colonnes nécessaires"),
        (r'SELECT\s+.*FROM\s+\w+\s*;(?!.*LIMIT)', 'SELECT sans LIMIT', 'low', "Ajouter LIMIT pour éviter de charger trop de données"),
        (r'\.findAll\s*\(\s*\)', 'findAll sans conditions', 'medium', "Ajouter des conditions ou pagination"),
        (r'\.find\s*\(\s*\{\s*\}\s*\)', 'MongoDB find vide', 'medium', "Ajouter des critères de recherche ou pagination"),
        (r'recursion|recursive(?!.*@cache|.*lru_cache)', 'Récursion sans cache', 'low', "Ajouter @lru_cache pour optimiser les appels récursifs"),
        (r'\.map\s*\([^)]*\)\s*\.filter\s*\(', 'Map puis filter (inefficace)', 'low', "Utiliser filter avant map pour réduire les itérations"),
        (r'\.forEach\s*\([^)]*await', 'Await dans forEach (non parallèle)', 'medium', "Utiliser Promise.all avec map pour paralléliser"),
        (r'Promise\.all\s*\(\s*\[\s*\]\s*\.map', 'Promise.all sans limite de concurrence', 'low', "Limiter la concurrence avec p-limit ou similaire"),
        (r'JSON\.parse\s*\(\s*JSON\.stringify', 'Deep clone inefficace', 'low', "Utiliser structuredClone() ou une lib de clonage"),
        (r'document\.querySelector.*for|for.*document\.querySelector', 'Query DOM dans boucle', 'medium', "Mettre en cache la requête DOM hors de la boucle"),
        (r'\.innerHTML\s*\+=', 'Concaténation innerHTML (lent)', 'medium', "Construire le HTML avant de l'assigner"),
    ]
    
    def analyze(self, content: str, filepath: str, lines: List[str] = None) -> List[Dict[str, Any]]:
        self.findings = []
        
        self.findings.extend(self._scan_patterns(content, filepath, self.PERFORMANCE_PATTERNS, 'performance'))
        
        return self.findings
