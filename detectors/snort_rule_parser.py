import re 

class SnortRuleParser:
    def __init__(self, rule_file):
        self.rule_file = rule_file

    def parse_rules(self):
        rules = []
        with open(self.rule_file, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines or commented lines
                if not line or line.startswith("#"):
                    continue

                rule = self.parse_snort_rule(line)
                if rule:
                    rules.append(rule)
        return rules

    def parse_snort_rule(self, line):  

        try:
            # Split header and options by the first '('
            if "(" not in line or ")" not in line:
                raise ValueError("Missing parentheses in rule")
                return None
            header, options_str = line.split("(", 1)
            options_str = options_str.rstrip(")")  # Remove the closing parenthesis
            options = self._parse_options(options_str)

            parts = header.strip().split()

            if len(parts) < 7:
                raise ValueError("Incomplete rule header.")

            action, protocol = parts[0], parts[1]
            # We assume destination port is in position 6 (index 6)
            dst_port = parts[6]

            # Use the "content" option for a simple regex rule
            pattern = options.get("content", None)

            # Skip binary/hex content rules for now
            if pattern and "|" in pattern:
                print(f"Skipping binary content rule: {options.get('msg', '')}")
                return None
            return {
                "id": int(options.get("sid", 0)),
                "description": options.get("msg", ""),
                "severity": "high",  # This can be customized or parsed from an option if available
                "protocol": protocol,
                "dst_port": int(dst_port) if dst_port.isdigit() else None,
                "type": "regex",
                "pattern": pattern  # We'll compile the regex later
            }

        except Exception as e:
            print(f"Failed to parse rule: {line}\nError: {e}")
            return None

    def _parse_options(self, options_str):
        """
        Parses the options inside the parentheses.
        Options are in the format: key:"value"; key:"value"; ...
        """
        options = {}
        # Split options on semicolon
        for part in options_str.split(";"):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                key, value = part.split(":", 1)
                # Remove surrounding quotes from value if present
                value = value.strip().strip('"')
                options[key.strip()] = value.strip().strip('"')
        return options
