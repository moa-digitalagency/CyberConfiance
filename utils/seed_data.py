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

def seed_tools(db):
    """Seed or update tools from JSON data (idempotent)"""
    from models import Tool
    
    tools_data = load_json_seed('tools_seed.json')
    if not tools_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for tool_data in tools_data:
        # Check if tool exists by name
        existing_tool = Tool.query.filter_by(name=tool_data['name']).first()
        
        if existing_tool:
            # Update existing tool
            existing_tool.description = tool_data['description']
            existing_tool.category = tool_data.get('category', '')
            existing_tool.url = tool_data.get('url', '')
            existing_tool.use_case = tool_data.get('use_case', '')
            existing_tool.dangers = tool_data.get('dangers', '')
            existing_tool.related_rules = tool_data.get('related_rules', '')
            existing_tool.related_scenarios = tool_data.get('related_scenarios', '')
            updated_count += 1
        else:
            # Create new tool
            new_tool = Tool(
                name=tool_data['name'],
                description=tool_data['description'],
                category=tool_data.get('category', ''),
                url=tool_data.get('url', ''),
                use_case=tool_data.get('use_case', ''),
                dangers=tool_data.get('dangers', ''),
                related_rules=tool_data.get('related_rules', ''),
                related_scenarios=tool_data.get('related_scenarios', '')
            )
            db.session.add(new_tool)
            seeded_count += 1
    
    db.session.commit()
    print(f"✓ Tools: {seeded_count} created, {updated_count} updated")

def seed_all_data(db):
    """Seed all data from JSON files"""
    print("Starting database seeding...")
    seed_rules(db)
    seed_scenarios(db)
    seed_glossary(db)
    seed_tools(db)
    print("Database seeding completed!")
