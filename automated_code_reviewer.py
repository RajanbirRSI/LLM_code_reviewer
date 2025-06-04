#!/usr/bin/env python3
"""
Simplified Code Reviewer - Check differences and evaluate with Ollama
"""

import subprocess
import re
import sys

def get_code_diff(branch_name="demo_test"):
    """Get diff between current branch and main branch"""
    try:
        result = subprocess.run(
            ['git', 'diff', f'origin/main...origin/autotest-review'],
            capture_output=True,
            text=True,
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
    
    prompt = f"""Review these code changes and provide a score out of 100.
Consider: code quality, functionality, security, and documentation.
End your response with "SCORE: X" where X is the numerical score.

Code changes:
```diff
{diff_content}
```"""
    
    try:
        print("Analyzing with Mistral...")
        result = subprocess.run(
            ['ollama', 'run', 'mistral', prompt],
            capture_output=True,
            text=True,
            check=True
        )
        
        response = result.stdout.strip()
        score = extract_score(response)
        return response, score
        
    except subprocess.TimeoutExpired:
        return "Analysis timed out", 50
    except FileNotFoundError:
        return "Ollama not found", 0
    except Exception as e:
        return f"Error: {e}", 50

def extract_score(response):
    """Extract score from AI response"""
    # Look for "SCORE: X" pattern
    match = re.search(r'SCORE:\s*(\d+)', response, re.IGNORECASE)
    if match:
        return int(match.group(1))
    
    # Fallback patterns
    patterns = [r'(\d+)/100', r'(\d+)\s+out\s+of\s+100', r'score\s*:\s*(\d+)']
    for pattern in patterns:
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            score = int(match.group(1))
            if 0 <= score <= 100:
                return score
    
    return 70  # Default score

def main():
    """Main function"""
    print("🔍 Checking for code differences...")
    
    # Get differences
    diff_content = get_code_diff()
    
    if not diff_content:
        print("No differences found")
        return
    
    print(f"Found {len(diff_content.splitlines())} lines of changes")
    
    # Evaluate with Ollama
    review_result, score = evaluate_with_ollama(diff_content)
    
    # Display results
    print("\n📋 Review Results:")
    print("=" * 50)
    print(review_result)
    print("=" * 50)
    print(f"🎯 Score: {score}/100")
    
    # Store results in variables for further use
    return {
        'diff': diff_content,
        'review': review_result,
        'score': score
    }

if __name__ == '__main__':
    results = main()
