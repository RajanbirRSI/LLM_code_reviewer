#!/usr/bin/env python3
"""
Code improver - Check differences and and suggets code improvements with vulnerabilities i.e., impact levels
"""

import json
import subprocess
import re
import sys
import os
import io
from typing import Dict, List, Tuple
import time
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8', line_buffering=True)

def get_code_diff(branch_name="demo_test"):
    """Get diff between current branch and main branch"""
    try:
        # Fetch branches first (needed for GitHub Actions)
        subprocess.run(['git', 'fetch', 'origin'], text=True, check=True, capture_output=True, encoding="utf-8")

        result = subprocess.run(
            ['git', 'diff', f'origin/main...origin/autotest-review'],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"Error getting diff: {e}")
        return ""

def evaluate_with_ollama(diff_content):
    """Send diff to Ollama Mistral for evaluation"""
    if not diff_content:
        return "No changes found", 85
    
    prompt = f"""
You are a Expert Software Developer with expertise in optimizing and improving code. Analyze the following code changes and provide a comprehensive improvements with impact classification accoridng to the following categories.

IMPROVEMENT FRAMEWORK:
Your analysis must fix suggestion for each of the following categories of issues with imact levels as defined below.
1. General Improvements: Code style, performance, architecture, best practices
2. Possible Issues: Logic errors, resource  
3. Defects: Security flaws, functional bugs, memory leaks, logic errors

IMPACT CLASSIFICATION
CRITICAL: Security vulnerabilities, system failures, data corruption risks
HIGH: Performance bottlenecks, major functionality issues, architectural flaws
MEDIUM: Code quality concerns, maintainability issues, minor bugs
LOW: Style improvements, documentation gaps, optimization opportunities

CODE CHANGES:
```diff
{diff_content}
```

REQUIRED RESPONSE FORMAT:
```json
{{
  "improvement_categories": {{
    "general_improvements": [
      {{
        "title": "Brief improvement title",
        "description": "Detailed description of the improvement opportunity",
        "impact_level": "CRITICAL|HIGH|MEDIUM|LOW",
        "category": "Code Style, Performance, Architecture, Best Practices",
        "fix_suggestion": "Specific steps to implement the improvement",
        "effort_required": "Low|Medium|High",
        "affected_areas": ["List of code areas affected"],
        "benefits": "Expected benefits from implementing this improvement"
      }}
    ],
    "possible_issues": [
      {{
        "title": "Brief issue title",
        "description": "Detailed description of the potential problem",
        "impact_level": "CRITICAL|HIGH|MEDIUM|LOW",
        "category": "Logic Error, Resource Leak, Race Condition, Data Integrity",
        "fix_suggestion": "Steps to prevent or resolve the issue",
        "effort_required": "Low|Medium|High",
        "affected_areas": ["List of code areas affected"],
        "prevention_strategy": "How to prevent this issue in the future"
      }}
    ],
    "defects": [
      {{
        "title": "Brief defect title",
        "description": "Clear description of the identified defect",
        "impact_level": "CRITICAL|HIGH|MEDIUM|LOW",
        "category": "Security Flaw, Functional Bug, Memory Leak, Logic Error",
        "fix_suggestion": "Immediate steps to resolve the defect",
        "effort_required": "Low|Medium|High",
        "affected_areas": ["List of code areas affected"],
        "root_cause": "Underlying cause of the defect"
      }}
    ]
  }}
}}
```

REVIEW GUIDELINES
1. Prioritize by Impact: Focus on CRITICAL and HIGH impact issues first
2. Be Actionable: Provide specific, implementable suggestions
3. Consider Context: Evaluate changes within the broader system context
4. Balance Criticism: Acknowledge good practices alongside areas for improvement
7. Be Constructive: Frame feedback as learning and improvement opportunities
"""  

    try:
        print("Analyzing with qwen2.5-coder:3b model")
        start_time = time.time()
        result = subprocess.run(
            ['ollama', 'run', 'qwen2.5-coder:3b'],
            input=prompt,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8"
        )
        
        response = result.stdout.strip()
        return response
        
    except subprocess.TimeoutExpired:
        return "Analysis timed out", 50
    except FileNotFoundError:
        return "Ollama not found", 0
    except Exception as e:
        return f"Error: {e}", 50

def _parse_llm_response(response: str) -> Dict:
    """Parse LLM response with robust error handling"""
    try:
        # Try to extract JSON from response
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        
        # Try to find JSON without code blocks
        json_match = re.search(r'(\{.*\})', response, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        
        # Fallback: Parse structured text response
        return "Failed to generate JSON response"
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return e
    except Exception as e:
        print(f"Unexpected parsing error: {e}")
        return e
    
class CodeImproverFormatter:
    """
    Formats code review JSON output into a beautiful GitHub-compatible markdown report.
    """
    def __init__(self):
        self.impact_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        self.category_icons = {
            'Security Flaw': '🔒',
            'Functional Bug': '🐛',
            'Performance': '⚡',
            'Code Style': '✨',
            'Architecture': '🏗️',
            'Best Practices': '👍',
            'Logic Error': '❌',
            'Memory Leak': '💾',
            'Race Condition': '⚠️',
            'Data Integrity': '📊'
        }

def format_review(response: Dict) -> Tuple[int, float]:
    markdown = []
    try:
        # Return empty if response is not a dictionary
        if not isinstance(response, dict) or 'improvement_categories' not in response:
            return 0, 0.0
            
        categories = response['improvement_categories']
        all_issues = []
        
        # Collect all issues from each category
        for category_name, issues in categories.items():
            for issue in issues:
                all_issues.append({
                    'category': issue.get('category', 'Unknown'),
                    'fix': issue.get('fix_suggestion', 'No suggestion provided'),
                    'impact': issue.get('impact_level', 'LOW')
                })
        
        total_issues = len(all_issues)
         
        return total_issues, all_issues
        
    except Exception as e:
        print(f"Error formatting review: {e}")
        return 0, 0.0

def format_issues_table(issues):
    """Format issues into markdown table"""
    if not issues or len(issues) == 0:  # More explicit empty list check
        return "No issues found"
    
    formatter = CodeImproverFormatter()
    table = "| Category | Impact | Fix Suggestion |\n"
    table += "|----------|---------|---------------|\n"
    
    for issue in issues:
        category = issue['category']
        impact = formatter.impact_icons.get(issue['impact'], '') + " " + issue['impact']
        fix = issue['fix'].replace('\n', ' ').strip()  # Clean up multiline fixes
        table += f"| {category} | {impact} | {fix} |\n"
        
    return table

def main():
    """Main function"""
    print("Checking for code differences...")
    
    # Get differences
    diff_content = get_code_diff()
    
    if not diff_content:
        print("No differences found")
        return
    
    print(f"Found {len(diff_content.splitlines())} lines of changes")
    
    # Evaluate with Ollama
    response = evaluate_with_ollama(diff_content)
    parsed_response = _parse_llm_response(response)
    # Format the code to print it in the comment
    total_issues, issues = format_review(parsed_response)    
    formatted_response = format_issues_table(issues)
    
    # Store results in variables for further use
    return formatted_response

if __name__ == '__main__':
    results = main()
