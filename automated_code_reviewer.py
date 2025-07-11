#!/usr/bin/env python3
"""
Simplified Code Reviewer - Check differences and evaluate with Ollama
"""

import subprocess
import re
import sys
import os
import io
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
        Code Review Task: Analyze and score this code 0-100.

        Code Quality (30 points): Is it clean, readable, and efficient?
        Security (30 points): Any vulnerabilities or data risks?
        Documentation (10 points): Are complex parts explained?
        Maintainability (10 points): Easy to modify and debug?
        Functionality (20 points): Does it work and handle errors?

        CODE CHANGES:
        ```diff
        {diff_content}
        ```\
        
        CHECK FOR:        
        Security bugs (SQL injection, XSS, hardcoded secrets)
        Code that might crash in production
        Missing error handling
        Poor performance patterns
        
        REQUIRED OUTPUT:
        Critical Issues: [max 3]
        Minor Issues: [max 2]
        Good Practices: [1-2 examples]
        Individual Scores: Quality=X/30, Security=X/30, Documentation=X/10, Maintainability=X/10, Functionality=X/20
        Score: X/100 [Aggregate of all individual scores]
        Reason: [1-2 sentences explaining the total score]
        """
#Lastly if the score is less than expected theshold that is 75, provide improvements in the code that should be done according to the metrics provided above so that score passes the excpected threshold
  
    try:
        print("Analyzing with qwen2.5-coder:3b model")
        result = subprocess.run(
            ['ollama', 'run', 'qwen2.5-coder:3b'],
            # ['ollama', 'run', 'mistral', prompt],
            # ['ollama', 'run', 'mistral:7b-instruct-q4_0', prompt],
            # ['ollama', 'run', 'llama3.2:1b', prompt],
            # ['ollama', 'run', 'phi3:mini', prompt],
            input=prompt,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8"
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
    
    return 75  # Default score

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
