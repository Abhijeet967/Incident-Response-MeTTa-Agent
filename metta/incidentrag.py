import re
from hyperon import MeTTa, E, S, ValueAtom

class IncidentRAG:
    def __init__(self, metta_instance: MeTTa):
        self.metta = metta_instance

    def query_indicator(self, indicator):
        """Find MITRE techniques linked to an indicator."""
        indicator = indicator.strip('"')
        query_str = f'!(match &self (indicator {indicator} $technique) $technique)'
        results = self.metta.run(query_str)
        print(f"Query indicator: {query_str}")
        print(f"Results: {results}")
        
        unique_techniques = list(set(str(r[0]) for r in results if r and len(r) > 0)) if results else []
        return unique_techniques

    def get_tactic(self, technique):
        """Find tactic for a technique."""
        technique = technique.strip('"')
        query_str = f'!(match &self (technique {technique} $tactic) $tactic)'
        results = self.metta.run(query_str)
        print(f"Query tactic: {query_str}")
        print(f"Results: {results}")
        
        return [str(r[0]) for r in results if r and len(r) > 0] if results else []

    def get_attack_phase(self, tactic):
        """Find attack phase for a tactic."""
        tactic = tactic.strip('"')
        query_str = f'!(match &self (tactic {tactic} $phase) $phase)'
        results = self.metta.run(query_str)
        print(f"Query phase: {query_str}")
        print(f"Results: {results}")
        
        return [r[0].get_object().value for r in results if r and len(r) > 0] if results else []

    def get_response_actions(self, attack_pattern):
        """Find response actions for an attack pattern."""
        attack_pattern = attack_pattern.strip('"')
        query_str = f'!(match &self (response {attack_pattern} $actions) $actions)'
        results = self.metta.run(query_str)
        print(f"Query response: {query_str}")
        print(f"Results: {results}")
        
        return [r[0].get_object().value for r in results if r and len(r) > 0] if results else []

    def get_severity(self, technique):
        """Find severity for a technique."""
        technique = technique.strip('"')
        query_str = f'!(match &self (severity {technique} $sev) $sev)'
        results = self.metta.run(query_str)
        print(f"Query severity: {query_str}")
        print(f"Results: {results}")
        
        return [r[0].get_object().value for r in results if r and len(r) > 0] if results else []

    def query_faq(self, question):
        """Retrieve FAQ answers."""
        query_str = f'!(match &self (faq "{question}" $answer) $answer)'
        results = self.metta.run(query_str)
        print(f"Query FAQ: {query_str}")
        print(f"Results: {results}")
        
        return results[0][0].get_object().value if results and results[0] else None

    def add_knowledge(self, relation_type, subject, object_value):
        """Add new knowledge dynamically."""
        if isinstance(object_value, str):
            object_value = ValueAtom(object_value)
        self.metta.space().add_atom(E(S(relation_type), S(subject), object_value))
        return f"Added {relation_type}: {subject} → {object_value}"
