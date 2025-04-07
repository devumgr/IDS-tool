import re
from datetime import datetime
from detectors.snort_rule_parser import SnortRuleParser

class SignatureDetector:
    def __init__(self, rule_file="rules/snort.rules"):
        parser = SnortRuleParser(rule_file)
        raw_rules = parser.parse_rules()
        self.compiled_rules = self.compile_rules(raw_rules)
        #self.rules = self.load_rules(rule_file)
        #self.compiled_rules = self.compile_rules()

    def compile_rules(self , rules):
        compiled_rules = []
        for rules in rules:
            try:
                compiled_rules.append({
                    'id': rules['id'],
                    'description': rules['description'],
                    'severity': rules['severity'],
                    'protocol': rules['protocol'].lower() if rules.get('protocol') else None,
                    'dst_port': int(rules['dst_port']) if rules.get('dst_port') else None,
                    'type': rules['type'],
                    'pattern': re.compile(rules['pattern'], re.IGNORECASE) if rules.get('pattern') else None
                })
            except re.error:
                print(f"Invalid regex pattern: {rules['pattern']}")
                continue
            return compiled_rules
    
    def analyze(self, packet):
        alerts = []
        for rule in self.compiled_rules:
            if self.match_rule(packet, rule):
                alerts.append({
                    'rule_id': rule['id'],
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'timestamp': datetime.now().isoformat(),
                    'packet': packet
                })
        return alerts
    
    def match_rule(self, packet, rule):
        # Implement the logic to match the packet against the rule
        # This is a placeholder function and should be implemented based on your rules
        if rule['protocol'] and packet.get['protocol',''].lower() != rule['protocol'].lower():
            return False

        # Port match
        if rule['dst_port'] and packet.get['dst_port',''] != rule['dst_port']:
            return False

        # Payload pattern match
        if rule['type'] == 'regex' and packet.get['payload','']:
            return bool(rule['pattern'].search(packet['payload']))
        
        return True
