import json
import os
from pathlib import Path

def load_json_seed(filename):
    """Load seed data from JSON file"""
    data_dir = Path(__file__).parent.parent / 'data'
    file_path = data_dir / filename
    
    if not file_path.exists():
        print(f"Warning: Seed file {filename} not found at {file_path}")
        return []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def seed_rules(db):
    """Seed or update rules from JSON data (idempotent)"""
    from models import Rule
    
    rules_data = load_json_seed('rules_seed.json')
    if not rules_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for rule_data in rules_data:
        # Check if rule exists by title
        existing_rule = Rule.query.filter_by(title=rule_data['title']).first()
        
        if existing_rule:
            # Update existing rule
            existing_rule.description = rule_data['description']
            existing_rule.order = rule_data['order']
            updated_count += 1
        else:
            # Create new rule
            new_rule = Rule(
                title=rule_data['title'],
                description=rule_data['description'],
                order=rule_data['order']
            )
            db.session.add(new_rule)
            seeded_count += 1
    
    db.session.commit()
    print(f"✓ Rules: {seeded_count} created, {updated_count} updated")

def seed_scenarios(db):
    """Seed or update scenarios from JSON data (idempotent)"""
    from models import Scenario
    
    scenarios_data = load_json_seed('scenarios_seed.json')
    if not scenarios_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for scenario_data in scenarios_data:
        # Check if scenario exists by title
        existing_scenario = Scenario.query.filter_by(title=scenario_data['title']).first()
        
        if existing_scenario:
            # Update existing scenario (only update provided fields)
            existing_scenario.description = scenario_data['description']
            if 'severity' in scenario_data:
                existing_scenario.severity = scenario_data['severity']
            if 'threat_type' in scenario_data:
                existing_scenario.threat_type = scenario_data['threat_type']
            if 'solution' in scenario_data:
                existing_scenario.solution = scenario_data['solution']
            updated_count += 1
        else:
            # Create new scenario
            new_scenario = Scenario(
                title=scenario_data['title'],
                description=scenario_data['description'],
                severity=scenario_data.get('severity', 'Moyen'),
                threat_type=scenario_data.get('threat_type', ''),
                solution=scenario_data.get('solution', '')
            )
            db.session.add(new_scenario)
            seeded_count += 1
    
    db.session.commit()
    print(f"✓ Scenarios: {seeded_count} created, {updated_count} updated")

def seed_glossary(db):
    """Seed or update glossary terms from JSON data (idempotent)"""
    from models import GlossaryTerm
    
    glossary_data = load_json_seed('glossary_seed.json')
    if not glossary_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for term_data in glossary_data:
        # Check if term exists by term name
        existing_term = GlossaryTerm.query.filter_by(term=term_data['term']).first()
        
        if existing_term:
            # Update existing term
            existing_term.definition = term_data['definition']
            updated_count += 1
        else:
            # Create new term
            new_term = GlossaryTerm(
                term=term_data['term'],
                definition=term_data['definition']
            )
            db.session.add(new_term)
            seeded_count += 1
    
    db.session.commit()
    print(f"✓ Glossary: {seeded_count} created, {updated_count} updated")

def seed_all_data(db):
    """Seed all data from JSON files"""
    print("Starting database seeding...")
    seed_rules(db)
    seed_scenarios(db)
    seed_glossary(db)
    print("Database seeding completed!")
