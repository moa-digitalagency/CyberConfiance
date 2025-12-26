"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Analyseur de prompts anti-injection avec detection de patterns malveillants.
"""

import re
import ast
import unicodedata
from urllib.parse import urlparse

class PromptAnalyzerService:
    
    def __init__(self):
        self.dangerous_functions = [
            'eval', 'exec', 'compile', 'execfile', 'input', '__import__',
            'open', 'file', 'os.system', 'subprocess', 'popen',
            'getattr', 'setattr', 'delattr', 'globals', 'locals',
            'vars', 'dir', 'type', 'object', 'class'
        ]
        
        self.injection_patterns = [
            (r'ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|commands?)', 'ignore_instructions', 'high'),
            (r'forget\s+(everything|all|what)\s+(you|i)\s+(told|said|wrote)', 'forget_command', 'high'),
            (r'disregard\s+(previous|all|above|prior)', 'disregard_command', 'high'),
            (r'new\s+instructions?:', 'new_instructions', 'high'),
            (r'system\s*:\s*you\s+are', 'system_override', 'critical'),
            (r'\[system\]|\[admin\]|\[developer\]', 'role_injection', 'critical'),
            (r'pretend\s+(you\s+are|to\s+be|you\'re)', 'pretend_command', 'medium'),
            (r'act\s+as\s+(if|though|a)', 'act_as_command', 'medium'),
            (r'roleplay\s+as', 'roleplay_command', 'medium'),
            (r'jailbreak|dan\s+mode|developer\s+mode', 'jailbreak_attempt', 'critical'),
            (r'bypass\s+(safety|content|filter|restriction)', 'bypass_attempt', 'critical'),
            (r'override\s+(safety|rules|guidelines)', 'override_attempt', 'critical'),
            (r'do\s+anything\s+now|unlimited\s+mode', 'unlimited_mode', 'critical'),
            (r'evil\s+mode|chaos\s+mode|unrestricted', 'evil_mode', 'critical'),
            (r'```(python|javascript|bash|shell|code).*?(eval|exec|system|subprocess)', 'hidden_code', 'high'),
            (r'base64[:\s]+[A-Za-z0-9+/=]{20,}', 'encoded_content', 'medium'),
            (r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}', 'unicode_escape', 'medium'),
            (r'<\|.*?\|>', 'special_tokens', 'high'),
            (r'\[\[.*?\]\]', 'bracket_injection', 'medium'),
            (r'{{.*?}}', 'template_injection', 'medium'),
            (r'prompt\s*injection|inject\s*prompt', 'explicit_injection', 'critical'),
        ]
        
        self.code_patterns = [
            (r'import\s+\w+', 'import_statement', 'medium'),
            (r'from\s+\w+\s+import', 'from_import', 'medium'),
            (r'def\s+\w+\s*\(', 'function_definition', 'low'),
            (r'class\s+\w+\s*[:\(]', 'class_definition', 'low'),
            (r'lambda\s*:', 'lambda_expression', 'medium'),
            (r'__\w+__', 'dunder_access', 'high'),
            (r'os\.(system|popen|exec|spawn)', 'os_command', 'critical'),
            (r'subprocess\.(call|run|Popen|check_output)', 'subprocess_command', 'critical'),
            (r'eval\s*\(', 'eval_call', 'critical'),
            (r'exec\s*\(', 'exec_call', 'critical'),
            (r'compile\s*\(', 'compile_call', 'high'),
            (r'globals\s*\(\s*\)|locals\s*\(\s*\)', 'scope_access', 'high'),
            (r'getattr\s*\(|setattr\s*\(', 'attr_manipulation', 'high'),
            (r'<script[^>]*>|</script>', 'script_tag', 'critical'),
            (r'javascript:', 'javascript_uri', 'high'),
            (r'onerror\s*=|onclick\s*=|onload\s*=', 'event_handler', 'high'),
        ]
        
        self.obfuscation_patterns = [
            (r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f]', 'invisible_chars', 'medium'),
            (r'[\u0300-\u036f]{3,}', 'combining_chars', 'medium'),
            (r'(.)\1{10,}', 'repeated_chars', 'low'),
            (r'[^\x00-\x7F]{20,}', 'non_ascii_block', 'low'),
            (r'&#x?[0-9a-fA-F]+;', 'html_entities', 'medium'),
            (r'%[0-9a-fA-F]{2}', 'url_encoding', 'low'),
            (r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', 'base64_block', 'medium'),
        ]
        
        self.emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"
            "\U0001F300-\U0001F5FF"
            "\U0001F680-\U0001F6FF"
            "\U0001F1E0-\U0001F1FF"
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "]+",
            flags=re.UNICODE
        )
        
        self.url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
        )
        
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        self._security_analyzer = None
    
    def _get_security_analyzer(self):
        if self._security_analyzer is None:
            from services.security.analyzer import SecurityAnalyzerService
            self._security_analyzer = SecurityAnalyzerService()
        return self._security_analyzer
    
    def extract_urls(self, text):
        urls = []
        matches = self.url_pattern.findall(text)
        for url in matches:
            url = url.rstrip('.,;:!?)"\']')
            if url and len(url) > 10:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        urls.append(url)
                except:
                    pass
        return list(set(urls))
    
    def extract_ips(self, text):
        ipv4_matches = self.ipv4_pattern.findall(text)
        ipv6_matches = self.ipv6_pattern.findall(text)
        
        ips = []
        private_ranges = [
            ('10.', '10.'),
            ('172.16.', '172.31.'),
            ('192.168.', '192.168.'),
            ('127.', '127.'),
            ('0.', '0.'),
        ]
        
        for ip in ipv4_matches:
            is_private = False
            for start, end in private_ranges:
                if ip.startswith(start):
                    is_private = True
                    break
            if not is_private:
                ips.append({'ip': ip, 'version': 'v4'})
        
        for ip in ipv6_matches:
            if not ip.startswith('::1') and not ip.startswith('fe80'):
                ips.append({'ip': ip, 'version': 'v6'})
        
        return ips
    
    def extract_domains(self, text):
        matches = self.domain_pattern.findall(text)
        
        common_words = {'example.com', 'test.com', 'localhost.local', 'domain.com'}
        excluded_tlds = {'.txt', '.pdf', '.doc', '.png', '.jpg', '.gif', '.css', '.js', '.html'}
        
        domains = []
        for domain in matches:
            domain_lower = domain.lower()
            if domain_lower in common_words:
                continue
            if any(domain_lower.endswith(ext) for ext in excluded_tlds):
                continue
            if '.' in domain and len(domain) > 4:
                domains.append(domain)
        
        return list(set(domains))
    
    def analyze_urls_with_security_service(self, urls, max_urls=5):
        results = []
        
        if not urls:
            return results
        
        try:
            security_analyzer = self._get_security_analyzer()
            
            for url in urls[:max_urls]:
                print(f"[Prompt] Analyse de securite pour URL: {url}")
                analysis = security_analyzer.analyze(url, 'url')
                
                if not analysis.get('error'):
                    results.append({
                        'url': url,
                        'threat_detected': analysis.get('threat_detected', False),
                        'threat_level': analysis.get('threat_level', 'inconnu'),
                        'sources_checked': analysis.get('sources_checked', 0),
                        'sources_with_threat': analysis.get('sources_with_threat', 0),
                        'all_threats': analysis.get('all_threats', []),
                        'source_results': analysis.get('source_results', {})
                    })
                else:
                    results.append({
                        'url': url,
                        'error': True,
                        'message': analysis.get('message', 'Erreur lors de l\'analyse')
                    })
        except Exception as e:
            print(f"[Prompt] Erreur analyse securite: {e}")
            for url in urls[:max_urls]:
                results.append({
                    'url': url,
                    'error': True,
                    'message': str(e)[:100]
                })
        
        return results
    
    def clean_text(self, text):
        cleaned = self.emoji_pattern.sub(' ', text)
        
        cleaned = re.sub(r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]', '', cleaned)
        
        cleaned = unicodedata.normalize('NFKC', cleaned)
        
        cleaned = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), cleaned)
        cleaned = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), cleaned)
        
        return cleaned
    
    def analyze_with_ast(self, text):
        issues = []
        
        code_blocks = re.findall(r'```(?:python|py)?\s*(.*?)```', text, re.DOTALL | re.IGNORECASE)
        code_blocks.extend(re.findall(r'`([^`]+)`', text))
        
        inline_code = re.findall(r'(?:^|\n)(\s*(?:import|from|def|class|if|for|while|try|with)\s+.*?)(?:\n|$)', text, re.MULTILINE)
        code_blocks.extend(inline_code)
        
        for code in code_blocks:
            code = code.strip()
            if not code or len(code) > 10000:
                continue
            
            try:
                tree = ast.parse(code, mode='exec')
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = None
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        
                        if func_name and func_name.lower() in [f.lower() for f in self.dangerous_functions]:
                            issues.append({
                                'type': 'dangerous_function',
                                'severity': 'critical',
                                'function': func_name,
                                'message': f"Appel a fonction dangereuse detecte: {func_name}()"
                            })
                    
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name in ['os', 'subprocess', 'sys', 'shutil', 'socket']:
                                issues.append({
                                    'type': 'dangerous_import',
                                    'severity': 'high',
                                    'module': alias.name,
                                    'message': f"Import de module sensible: {alias.name}"
                                })
                    
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and node.module in ['os', 'subprocess', 'sys', 'shutil', 'socket']:
                            issues.append({
                                'type': 'dangerous_import',
                                'severity': 'high',
                                'module': node.module,
                                'message': f"Import depuis module sensible: {node.module}"
                            })
                    
                    elif isinstance(node, ast.Attribute):
                        if node.attr.startswith('__') and node.attr.endswith('__'):
                            dangerous_dunders = ['__subclasses__', '__class__', '__bases__', '__mro__', 
                                                '__globals__', '__builtins__', '__code__', '__reduce__']
                            severity = 'critical' if node.attr in dangerous_dunders else 'high'
                            issues.append({
                                'type': 'dunder_access',
                                'severity': severity,
                                'attribute': node.attr,
                                'message': f"Acces a attribut special: {node.attr}"
                            })
            
            except SyntaxError:
                pass
            except (ValueError, TypeError, RecursionError):
                pass
            except Exception:
                pass
        
        return issues
    
    def analyze_patterns(self, text):
        issues = []
        text_lower = text.lower()
        
        for pattern, issue_type, severity in self.injection_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                issues.append({
                    'type': issue_type,
                    'severity': severity,
                    'category': 'injection',
                    'message': self.get_issue_message(issue_type),
                    'matches': len(matches)
                })
        
        for pattern, issue_type, severity in self.code_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                issues.append({
                    'type': issue_type,
                    'severity': severity,
                    'category': 'code',
                    'message': self.get_issue_message(issue_type),
                    'matches': len(matches)
                })
        
        for pattern, issue_type, severity in self.obfuscation_patterns:
            matches = re.findall(pattern, text)
            if matches:
                issues.append({
                    'type': issue_type,
                    'severity': severity,
                    'category': 'obfuscation',
                    'message': self.get_issue_message(issue_type),
                    'matches': len(matches)
                })
        
        return issues
    
    def get_issue_message(self, issue_type):
        messages = {
            'ignore_instructions': "Tentative d'ignorer les instructions précédentes",
            'forget_command': "Commande pour oublier le contexte",
            'disregard_command': "Commande pour ignorer les directives",
            'new_instructions': "Injection de nouvelles instructions",
            'system_override': "Tentative de redéfinition du rôle système",
            'role_injection': "Injection de rôle (admin/system/developer)",
            'pretend_command': "Commande de simulation de rôle",
            'act_as_command': "Commande 'agir comme'",
            'roleplay_command': "Commande de jeu de rôle",
            'jailbreak_attempt': "Tentative de jailbreak",
            'bypass_attempt': "Tentative de contournement des filtres",
            'override_attempt': "Tentative de contournement des règles",
            'unlimited_mode': "Activation de mode illimité",
            'evil_mode': "Activation de mode malveillant",
            'hidden_code': "Code potentiellement malveillant détecté",
            'encoded_content': "Contenu encodé en base64",
            'unicode_escape': "Séquences d'échappement Unicode",
            'special_tokens': "Tokens spéciaux détectés",
            'bracket_injection': "Injection par crochets",
            'template_injection': "Injection de template",
            'explicit_injection': "Mention explicite d'injection de prompt",
            'import_statement': "Instruction d'import Python",
            'from_import': "Import depuis un module",
            'function_definition': "Définition de fonction",
            'class_definition': "Définition de classe",
            'lambda_expression': "Expression lambda",
            'dunder_access': "Accès aux attributs spéciaux (__)",
            'os_command': "Commande système OS",
            'subprocess_command': "Exécution de sous-processus",
            'eval_call': "Appel à eval() - très dangereux",
            'exec_call': "Appel à exec() - très dangereux",
            'compile_call': "Appel à compile()",
            'scope_access': "Accès aux variables globales/locales",
            'attr_manipulation': "Manipulation d'attributs",
            'script_tag': "Balise script HTML",
            'javascript_uri': "URI JavaScript",
            'event_handler': "Gestionnaire d'événements HTML",
            'invisible_chars': "Caractères invisibles (zero-width)",
            'combining_chars': "Caractères de combinaison excessifs",
            'repeated_chars': "Caractères répétés excessivement",
            'non_ascii_block': "Grand bloc de caractères non-ASCII",
            'html_entities': "Entités HTML encodées",
            'url_encoding': "Encodage URL",
            'base64_block': "Grand bloc encodé en base64",
            'dangerous_function': "Fonction dangereuse détectée",
            'dangerous_import': "Import de module dangereux",
        }
        return messages.get(issue_type, f"Problème détecté: {issue_type}")
    
    def analyze_prompt(self, prompt_text, analyze_urls=True):
        result = {
            'success': True,
            'prompt_length': len(prompt_text),
            'threat_detected': False,
            'threat_level': 'safe',
            'injection_detected': False,
            'code_detected': False,
            'obfuscation_detected': False,
            'urls_detected': False,
            'ips_detected': False,
            'issues': [],
            'cleaned_text': None,
            'summary': {},
            'url_analysis': None,
            'ip_analysis': None,
            'domain_analysis': None
        }
        
        if not prompt_text or not prompt_text.strip():
            result['error'] = "Texte vide ou invalide"
            result['success'] = False
            return result
        
        cleaned_text = self.clean_text(prompt_text)
        result['cleaned_text'] = cleaned_text if cleaned_text != prompt_text else None
        
        pattern_issues = self.analyze_patterns(prompt_text)
        result['issues'].extend(pattern_issues)
        
        if cleaned_text != prompt_text:
            cleaned_issues = self.analyze_patterns(cleaned_text)
            for issue in cleaned_issues:
                issue['found_in'] = 'cleaned_text'
                if issue not in result['issues']:
                    result['issues'].append(issue)
        
        ast_issues = self.analyze_with_ast(prompt_text)
        result['issues'].extend(ast_issues)
        
        extracted_urls = self.extract_urls(prompt_text)
        extracted_ips = self.extract_ips(prompt_text)
        extracted_domains = self.extract_domains(prompt_text)
        
        if extracted_urls:
            result['urls_detected'] = True
            result['url_analysis'] = {
                'urls_found': extracted_urls,
                'count': len(extracted_urls),
                'security_results': []
            }
            
            result['issues'].append({
                'type': 'urls_in_prompt',
                'severity': 'medium',
                'category': 'urls',
                'message': f"{len(extracted_urls)} URL(s) detectee(s) dans le texte",
                'urls': extracted_urls[:10]
            })
            
            if analyze_urls:
                security_results = self.analyze_urls_with_security_service(extracted_urls)
                result['url_analysis']['security_results'] = security_results
                
                for sec_result in security_results:
                    if sec_result.get('threat_detected') and not sec_result.get('error'):
                        threat_level = sec_result.get('threat_level', 'modere')
                        severity_map = {'critique': 'critical', 'eleve': 'high', 'modere': 'medium', 'sur': 'low'}
                        severity = severity_map.get(threat_level, 'medium')
                        
                        result['issues'].append({
                            'type': 'malicious_url_detected',
                            'severity': severity,
                            'category': 'security',
                            'message': f"URL malveillante detectee: {sec_result['url'][:50]}...",
                            'url': sec_result['url'],
                            'sources_with_threat': sec_result.get('sources_with_threat', 0),
                            'all_threats': sec_result.get('all_threats', [])
                        })
        
        if extracted_ips:
            result['ips_detected'] = True
            result['ip_analysis'] = {
                'ips_found': extracted_ips,
                'count': len(extracted_ips)
            }
            
            result['issues'].append({
                'type': 'ips_in_prompt',
                'severity': 'medium',
                'category': 'ips',
                'message': f"{len(extracted_ips)} adresse(s) IP detectee(s) dans le texte",
                'ips': extracted_ips[:10]
            })
        
        if extracted_domains:
            url_domains = set()
            for url in extracted_urls:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        url_domains.add(parsed.netloc.lower().split(':')[0])
                except:
                    pass
            
            standalone_domains = [d for d in extracted_domains if d.lower() not in url_domains]
            
            if standalone_domains:
                result['domain_analysis'] = {
                    'domains_found': standalone_domains,
                    'count': len(standalone_domains)
                }
                
                result['issues'].append({
                    'type': 'domains_in_prompt',
                    'severity': 'low',
                    'category': 'domains',
                    'message': f"{len(standalone_domains)} domaine(s) detecte(s) dans le texte",
                    'domains': standalone_domains[:10]
                })
        
        injection_issues = [i for i in result['issues'] if i.get('category') == 'injection' or i.get('type') in ['ignore_instructions', 'system_override', 'jailbreak_attempt']]
        code_issues = [i for i in result['issues'] if i.get('category') == 'code' or i.get('type') in ['dangerous_function', 'dangerous_import']]
        obfuscation_issues = [i for i in result['issues'] if i.get('category') == 'obfuscation']
        url_issues = [i for i in result['issues'] if i.get('category') in ['urls', 'security']]
        ip_issues = [i for i in result['issues'] if i.get('category') == 'ips']
        
        result['injection_detected'] = len(injection_issues) > 0
        result['code_detected'] = len(code_issues) > 0
        result['obfuscation_detected'] = len(obfuscation_issues) > 0
        
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for issue in result['issues']:
            severity = issue.get('severity', 'low')
            score = severity_scores.get(severity, 1)
            max_severity = max(max_severity, score)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if max_severity >= 4 or severity_counts.get('critical', 0) > 0:
            result['threat_level'] = 'critical'
            result['threat_detected'] = True
        elif max_severity >= 3 or severity_counts.get('high', 0) >= 2:
            result['threat_level'] = 'high'
            result['threat_detected'] = True
        elif max_severity >= 2 or severity_counts.get('medium', 0) >= 3:
            result['threat_level'] = 'medium'
            result['threat_detected'] = len(result['issues']) > 3
        elif len(result['issues']) > 0:
            result['threat_level'] = 'low'
        else:
            result['threat_level'] = 'safe'
        
        result['summary'] = {
            'total_issues': len(result['issues']),
            'severity_counts': severity_counts,
            'injection_count': len(injection_issues),
            'code_count': len(code_issues),
            'obfuscation_count': len(obfuscation_issues),
            'url_count': len(extracted_urls),
            'ip_count': len(extracted_ips),
            'url_security_issues': len([i for i in url_issues if i.get('type') == 'malicious_url_detected'])
        }
        
        return result
