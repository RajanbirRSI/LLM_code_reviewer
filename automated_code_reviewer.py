#!/usr/bin/env python3
"""
Simplified Code Reviewer - Check differences and evaluate with Ollama
"""

import subprocess
import re
import sys
import sys

def get_code_diff(branch_name="demo_test"):
    """Get diff between current branch and main branch"""
    try:
        # Fetch branches first (needed for GitHub Actions)
        subprocess.run(['git', 'fetch', 'origin'], check=True, capture_output=True, encoding="utf-8")

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
    
    prompt = f"""You are an expert code reviewer. Analyze the provided code changes and assign a score from 0-100 based on the weighted criteria below.
        Consider: 
        1. Code quality (30 points)
            for eg-Ensure code is DRY (Don't Repeat Yourself)
        2. Security (30 points)
            for eg- Check for any security red flags
            -Watch out for code that could lead to GDPR violations
        3. Code comments/documentation (10 points)
            for eg- Make sure all code has docstrings and use style
        4. Maintainability (10 points)
            for eg- code is modular and handles exception properly with logging
        5. Functionality (20 points)
            for eg- code works as intended and handles edge cases
    End your response with "SCORE: X/100" where X is the numerical score.
        
Code changes:
```diff
{diff_content}
```\
Lastly if the score is less than expected theshold that is 75, provide improvements in the code that should be done according to the metrics provided above so that score passes the excpected threshold
"""
  
    try:
        print("Analyzing with Quantized llma 3.2 model...")
        result = subprocess.run(
            ['ollama', 'run', 'hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:IQ3_M', prompt],
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
    # Primary pattern: Look for "Total Score:** X/100" or similar
    patterns = [
        r'(?:total\s+score|final\s+score|score)[:*\s]*(\d+)/100',  # "Total Score:** 75/100"
        r'(\d+)/100',  # Simple "75/100" format
        r'SCORE:\s*(\d+)',  # "SCORE: 75"
        r'score\s*[:=]\s*(\d+)',  # "score: 75" or "score = 75"
        r'(\d+)\s+out\s+of\s+100',  # "75 out of 100"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, response, re.IGNORECASE)
        if match:
            score = int(match.group(1))
            if 0 <= score <= 100:
                return score
    
    return 70  # Default score

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
    review_result, score = evaluate_with_ollama(diff_content)
    
    # Display results
    print("\nReview Results:")
    print("=" * 50)
    print(review_result)
    print("=" * 50)
    print(f"Score: {score}/100")
    
    # Store results in variables for further use
    return {
        'diff': diff_content,
        'review': review_result,
        'score': score
    }

if __name__ == '__main__':
    results = main()
