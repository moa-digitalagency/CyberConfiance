"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Service de quiz interactif avec calcul des scores.
"""

import json
import os

class QuizService:
    @staticmethod
    def load_quiz_data():
        # Get the project root directory (two levels up from services/quiz/)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        quiz_file = os.path.join(project_root, 'data', 'quiz_questions.json')
        with open(quiz_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    @staticmethod
    def calculate_scores(answers):
        quiz_data = QuizService.load_quiz_data()
        questions = quiz_data['questions']
        max_scores = quiz_data['scoring']['max_score']
        
        scores = {
            'vigilance': 0,
            'security': 0,
            'hygiene': 0
        }
        
        for question in questions:
            question_id = str(question['id'])
            if question_id in answers:
                selected_option_value = int(answers[question_id])
                
                for option in question['options']:
                    if option['value'] == selected_option_value:
                        weights = option['weights']
                        scores['vigilance'] += weights.get('vigilance', 0)
                        scores['security'] += weights.get('security', 0)
                        scores['hygiene'] += weights.get('hygiene', 0)
                        break
        
        percentages = {
            'vigilance': round((scores['vigilance'] / max_scores['vigilance']) * 100),
            'security': round((scores['security'] / max_scores['security']) * 100),
            'hygiene': round((scores['hygiene'] / max_scores['hygiene']) * 100)
        }
        
        overall_score = round((percentages['vigilance'] + percentages['security'] + percentages['hygiene']) / 3)
        
        return {
            'raw_scores': scores,
            'percentages': percentages,
            'overall_score': overall_score
        }
    
    @staticmethod
    def get_level_from_score(score):
        quiz_data = QuizService.load_quiz_data()
        levels = quiz_data['scoring']['levels']
        
        for level_key, level_data in levels.items():
            if level_data['min'] <= score <= level_data['max']:
                return {
                    'key': level_key,
                    'label': level_data['label'],
                    'color': level_data['color']
                }
        
        return {
            'key': 'moyen',
            'label': 'Moyen',
            'color': '#f59e0b'
        }
    
    @staticmethod
    def get_recommendations(overall_score, answers):
        from models import Rule, Tool
        
        quiz_data = QuizService.load_quiz_data()
        level_info = QuizService.get_level_from_score(overall_score)
        level_key = level_info['key']
        
        recommendation_data = quiz_data['recommendations'].get(level_key, quiz_data['recommendations']['moyen'])
        
        priority_rule_ids = recommendation_data.get('priority_rules', [])
        rules = Rule.query.filter(Rule.id.in_(priority_rule_ids)).all()
        
        weak_areas = QuizService.identify_weak_areas(answers)
        
        all_tools = Tool.query.all()
        
        return {
            'level': level_info,
            'title': recommendation_data['title'],
            'message': recommendation_data['message'],
            'priority_rules': rules,
            'weak_areas': weak_areas,
            'suggested_tools': all_tools[:6]
        }
    
    @staticmethod
    def identify_weak_areas(answers):
        quiz_data = QuizService.load_quiz_data()
        questions = quiz_data['questions']
        weak_areas = []
        
        for question in questions:
            question_id = str(question['id'])
            if question_id in answers:
                selected_value = int(answers[question_id])
                
                if selected_value <= 1:
                    weak_areas.append({
                        'question': question['question'],
                        'description': question['description'],
                        'related_rules': question.get('related_rules', []),
                        'category': question.get('category', 'general')
                    })
        
        return weak_areas
