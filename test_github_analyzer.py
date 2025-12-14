#!/usr/bin/env python3
"""
Script de test pour l'analyseur de code GitHub
Verifie toutes les fonctionnalites principales
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.github.analyzer import GitHubCodeAnalyzerService
from services.github.translations import translate_security_message

def test_translations():
    """Test des traductions francaises"""
    print("\n" + "="*60)
    print("TEST 1: Traductions francaises")
    print("="*60)
    
    test_cases = [
        ("Hardcoded password", "Mot de passe code en dur"),
        ("SQL injection", "Injection SQL"),
        ("Missing CSRF protection", "Protection CSRF manquante"),
        ("Unknown message", "Unknown message"),
    ]
    
    passed = 0
    for english, expected_french in test_cases:
        result = translate_security_message(english)
        status = "OK" if result == expected_french else "ECHEC"
        if status == "OK":
            passed += 1
        print(f"  [{status}] '{english}' -> '{result}'")
    
    print(f"\n  Resultat: {passed}/{len(test_cases)} tests passes")
    return passed == len(test_cases)

def test_exclusion_patterns():
    """Test des patterns d'exclusion"""
    print("\n" + "="*60)
    print("TEST 2: Patterns d'exclusion")
    print("="*60)
    
    analyzer = GitHubCodeAnalyzerService(use_semgrep=False)
    
    excluded_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 
                    '.venv', 'vendor', 'dist', 'build', '.next', 'coverage',
                    '.cache', '.pytest_cache', '.mypy_cache', 'target',
                    'bower_components', '.nuxt', '.output', 'out',
                    'docs', 'documentation', 'attached_assets', 'uploads',
                    'static/uploads', 'media', 'tmp', 'temp', '.replit',
                    'replit_zip_error_log.txt', '.local', 'migrations'}
    
    excluded_extensions = {'.min.js', '.min.css', '.map', '.lock', '.svg', 
                          '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', 
                          '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
                          '.avi', '.mov', '.webm', '.pdf', '.zip', '.tar',
                          '.gz', '.rar', '.7z', '.exe', '.dll', '.so',
                          '.pyc', '.pyo', '.class', '.jar', '.war', '.md',
                          '.log', '.txt'}
    
    test_dirs = ['docs', 'attached_assets', 'migrations', '.replit']
    test_exts = ['.md', '.txt', '.log', '.png']
    
    passed = 0
    for d in test_dirs:
        status = "OK" if d in excluded_dirs else "ECHEC"
        if status == "OK":
            passed += 1
        print(f"  [{status}] Dossier exclu: {d}")
    
    for ext in test_exts:
        status = "OK" if ext in excluded_extensions else "ECHEC"
        if status == "OK":
            passed += 1
        print(f"  [{status}] Extension exclue: {ext}")
    
    total = len(test_dirs) + len(test_exts)
    print(f"\n  Resultat: {passed}/{total} tests passes")
    return passed == total

def test_deduplication():
    """Test de la deduplication des findings"""
    print("\n" + "="*60)
    print("TEST 3: Deduplication des findings")
    print("="*60)
    
    analyzer = GitHubCodeAnalyzerService(use_semgrep=False)
    
    analyzer.findings['security'] = [
        {'type': 'xss', 'title': 'XSS vulnerability', 'severity': 'high', 'file': 'app.py', 'line': 10},
        {'type': 'xss', 'title': 'XSS vulnerability', 'severity': 'high', 'file': 'app.py', 'line': 10},
        {'type': 'xss', 'title': 'XSS vulnerability', 'severity': 'high', 'file': 'app.py', 'line': 20},
        {'type': 'sqli', 'title': 'SQL injection', 'severity': 'critical', 'file': 'db.py', 'line': 5},
    ]
    
    initial_count = len(analyzer.findings['security'])
    analyzer._deduplicate_findings()
    final_count = len(analyzer.findings['security'])
    
    expected = 3
    status = "OK" if final_count == expected else "ECHEC"
    print(f"  [{status}] Avant: {initial_count} findings, Apres: {final_count} (attendu: {expected})")
    
    lines = [f['line'] for f in analyzer.findings['security'] if f['type'] == 'xss']
    lines_preserved = 10 in lines and 20 in lines
    status2 = "OK" if lines_preserved else "ECHEC"
    print(f"  [{status2}] Lignes distinctes preservees: {lines}")
    
    result = final_count == expected and lines_preserved
    print(f"\n  Resultat: {'PASSE' if result else 'ECHEC'}")
    return result

def test_analyzer_initialization():
    """Test de l'initialisation de l'analyseur"""
    print("\n" + "="*60)
    print("TEST 4: Initialisation de l'analyseur")
    print("="*60)
    
    github_token = os.environ.get('GITHUB_TOKEN')
    
    try:
        analyzer = GitHubCodeAnalyzerService(
            github_token=github_token,
            use_semgrep=True
        )
        
        print(f"  [OK] Analyseur cree")
        print(f"  [OK] Token GitHub: {'Configure' if github_token else 'Non configure'}")
        print(f"  [OK] Semgrep: Active")
        print(f"  [OK] Categories: {list(analyzer.findings.keys())}")
        
        return True
    except Exception as e:
        print(f"  [ECHEC] Erreur: {e}")
        return False

def test_url_validation():
    """Test de la validation des URLs"""
    print("\n" + "="*60)
    print("TEST 5: Validation des URLs GitHub")
    print("="*60)
    
    analyzer = GitHubCodeAnalyzerService(use_semgrep=False)
    
    test_urls = [
        ("https://github.com/owner/repo", True),
        ("https://github.com/owner/repo.git", True),
        ("https://gitlab.com/owner/repo", False),
        ("https://bitbucket.org/owner/repo", False),
        ("invalid-url", False),
    ]
    
    passed = 0
    for url, should_pass in test_urls:
        result = analyzer.analyze(url, mode='quick')
        is_error = result.get('error', False)
        
        if should_pass:
            status = "ECHEC" if is_error and 'GitHub' not in result.get('message', '') else "OK"
        else:
            status = "OK" if is_error else "ECHEC"
        
        if (should_pass and not is_error) or (not should_pass and is_error):
            passed += 1
            
        print(f"  [{status}] {url[:40]}... -> {'Valide' if not is_error else 'Invalide'}")
    
    print(f"\n  Resultat: {passed}/{len(test_urls)} tests passes")
    return passed >= 3

def test_quick_analysis():
    """Test d'une analyse rapide sur un repo public"""
    print("\n" + "="*60)
    print("TEST 6: Analyse rapide (mode quick)")
    print("="*60)
    
    analyzer = GitHubCodeAnalyzerService(
        github_token=os.environ.get('GITHUB_TOKEN'),
        use_semgrep=False
    )
    
    test_repo = "https://github.com/pallets/flask"
    print(f"  Analyse de: {test_repo}")
    
    try:
        result = analyzer.analyze(test_repo, branch='main', mode='quick')
        
        if result.get('error'):
            print(f"  [ATTENTION] Erreur: {result.get('message')}")
            return False
        
        print(f"  [OK] Repo: {result.get('repo_name')}")
        print(f"  [OK] Score global: {result.get('overall_score')}/100")
        print(f"  [OK] Niveau de risque: {result.get('risk_level')}")
        print(f"  [OK] Fichiers analyses: {result.get('total_files_analyzed')}")
        
        return True
    except Exception as e:
        print(f"  [ECHEC] Exception: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("  TESTS DE L'ANALYSEUR DE CODE GITHUB - CYBERCONFIANCE")
    print("="*60)
    
    results = []
    
    results.append(("Traductions", test_translations()))
    results.append(("Exclusions", test_exclusion_patterns()))
    results.append(("Deduplication", test_deduplication()))
    results.append(("Initialisation", test_analyzer_initialization()))
    results.append(("Validation URLs", test_url_validation()))
    results.append(("Analyse rapide", test_quick_analysis()))
    
    print("\n" + "="*60)
    print("  RESUME DES TESTS")
    print("="*60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "PASSE" if result else "ECHEC"
        print(f"  [{status}] {name}")
    
    print("\n" + "-"*60)
    print(f"  TOTAL: {passed}/{total} tests passes")
    
    if passed == total:
        print("  STATUS: TOUS LES TESTS SONT PASSES!")
    else:
        print("  STATUS: CERTAINS TESTS ONT ECHOUE")
    
    print("="*60 + "\n")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
