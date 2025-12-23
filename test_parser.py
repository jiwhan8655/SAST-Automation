#!/usr/bin/env python3
"""
Print all SARIF issues with detailed information
"""

import json
from sarif.parser import parse_sarif


def print_issue_detailed(issue, index):
    """Print a single issue with all details"""
    print("=" * 80)
    print(f"ISSUE #{index}")
    print("=" * 80)
    
    # Basic info
    print(f"Issue ID: {issue['issue_id']}")
    print(f"Tool: {issue['tool']['name']} (v{issue['tool']['version']})")
    print(f"Run Index: {issue['tool']['run_index']}")
    print()
    
    # Rule info
    print("RULE:")
    print(f"  ID: {issue['rule']['id']}")
    print(f"  Name: {issue['rule'].get('name', 'N/A')}")
    print(f"  Description: {issue['rule'].get('description', 'N/A')}")
    if issue['rule'].get('tags'):
        print(f"  Tags: {', '.join(issue['rule']['tags'])}")
    print()
    
    # SAST info
    print("SEVERITY:")
    print(f"  {issue['sast'].get('severity', 'N/A')}")
    print()
    
    # Message
    print("MESSAGE:")
    message = issue.get('message', '')
    if message:
        # Split by newlines and show count
        lines = message.split('\n')
        if len(lines) > 3:
            print(f"  {lines[0]}")
            print(f"  {lines[1]}")
            print(f"  ... ({len(lines) - 2} more message variants)")
        else:
            for line in lines:
                print(f"  {line}")
    else:
        print("  N/A")
    print()
    
    # Primary location
    print("PRIMARY LOCATION:")
    primary = issue['locations']['primary']
    uri = primary.get('uri', 'N/A')
    start = primary['region'].get('startLine', 'N/A')
    end = primary['region'].get('endLine', 'N/A')
    print(f"  File: {uri}")
    print(f"  Lines: {start}-{end}")
    print()
    
    # Related locations (data flow)
    if 'related' in issue['locations']:
        related = issue['locations']['related']
        print(f"DATA FLOW ({len(related)} steps):")
        
        # Show first 5 steps
        for i, loc in enumerate(related[:5], 1):
            uri = loc.get('uri', 'N/A')
            line = loc.get('region', {}).get('startLine', 'N/A')
            print(f"  Step {i}: {uri}:{line}")
        
        if len(related) > 5:
            print(f"  ... ({len(related) - 5} more steps)")
    else:
        print("DATA FLOW: None")
    
    print()


def print_summary(issues):
    """Print summary statistics"""
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    total = len(issues)
    print(f"Total Issues: {total}")
    
    # Count by rule
    rule_counts = {}
    for issue in issues:
        rule_id = issue['rule']['id']
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
    
    print(f"\nIssues by Rule:")
    for rule_id, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        print(f"  {rule_id}: {count}")
    
    # Count by severity
    severity_counts = {}
    for issue in issues:
        severity = issue['sast'].get('severity', 'unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\nIssues by Severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    # Data flow statistics
    with_flow = sum(1 for issue in issues if 'related' in issue['locations'])
    without_flow = total - with_flow
    
    print(f"\nData Flow:")
    print(f"  With data flow: {with_flow}")
    print(f"  Without data flow: {without_flow}")
    
    if with_flow > 0:
        max_steps = max(
            len(issue['locations']['related']) 
            for issue in issues 
            if 'related' in issue['locations']
        )
        avg_steps = sum(
            len(issue['locations']['related']) 
            for issue in issues 
            if 'related' in issue['locations']
        ) / with_flow
        
        print(f"  Max data flow steps: {max_steps}")
        print(f"  Avg data flow steps: {avg_steps:.1f}")


def export_to_json(issues, filename='parsed_issues.json'):
    """Export issues to JSON file"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(issues, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Exported to {filename}")


def main():
    # Load SARIF file
    sarif_file = 'directus-codeql.sarif'
    
    print(f"Loading SARIF file: {sarif_file}")
    
    with open(sarif_file, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    
    # Parse
    print("Parsing...")
    issues = parse_sarif(sarif_data)
    
    print(f"\n✓ Found {len(issues)} issues\n")
    
    # Print all issues
    for i, issue in enumerate(issues, 1):
        print_issue_detailed(issue, i)
    
    # Print summary
    print_summary(issues)
    
    # Export to JSON
    export_to_json(issues)
    
    print("\n" + "=" * 80)
    print("✅ DONE!")
    print("=" * 80)


if __name__ == "__main__":
    main()