# json_only.py
import json
from sarif.parser import parse_sarif

# Load SARIF
with open('directus-codeql.sarif', 'r', encoding='utf-8') as f:
    sarif_data = json.load(f)

# Parse
issues = parse_sarif(sarif_data)

# Export to JSON only
with open('parsed_issues.json', 'w', encoding='utf-8') as f:
    json.dump(issues, f, indent=2, ensure_ascii=False)

print(f"✓ Exported {len(issues)} issues to parsed_issues.json")