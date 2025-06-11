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
        # Fetch branches first (needed for GitHub Actions)
        subprocess.run(['git', 'fetch', 'origin'], check=True, capture_output=True)

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
    
    prompt = f"""You are an expert code reviewer. Analyze the provided code changes and assign a score from 0-100 based on the weighted criteria below.

## SCORING RUBRIC (Total: 100 points)

### 1. CODE QUALITY (30 points)
- **Readability & Style** (10 pts): Consistent naming, formatting, clear structure
- **DRY Principle** (10 pts): No code duplication, proper abstraction
- **Design Patterns** (10 pts): Appropriate use of patterns, SOLID principles

### 2. FUNCTIONALITY (25 points)
- **Logic Correctness** (15 pts): Code works as intended, handles edge cases
- **Performance** (10 pts): Efficient algorithms, no obvious bottlenecks

### 3. SECURITY (20 points)
- **Vulnerability Assessment** (15 pts): No SQL injection, XSS, insecure dependencies
- **Data Privacy** (5 pts): GDPR compliance, secure data handling

### 4. DOCUMENTATION (15 points)
- **Code Documentation** (10 pts): Comprehensive docstrings, inline comments for complex logic
- **API Documentation** (5 pts): Clear function/method signatures and descriptions

### 5. MAINTAINABILITY (10 points)
- **Modularity** (5 pts): Well-structured, loosely coupled components
- **Error Handling** (5 pts): Proper exception handling and logging

## ANALYSIS FORMAT

**STRENGTHS:**
- List 2-3 specific positive aspects

**ISSUES FOUND:**
- **Critical** (0-40 pts): Security vulnerabilities, broken functionality
- **Major** (41-70 pts): Poor design, significant code quality issues
- **Minor** (71-90 pts): Style inconsistencies, missing documentation
- **Suggestions** (91-100 pts): Optimization opportunities, best practice improvements

**DETAILED BREAKDOWN:**
- Code Quality: X/30
- Functionality: X/25  
- Security: X/20
- Documentation: X/15
- Maintainability: X/10

**ACTIONABLE RECOMMENDATIONS:**
1. [Specific fix for highest priority issue]
2. [Next priority fix]
3. [Improvement suggestion]

**FINAL SCORE: X/100**

## SCORING GUIDELINES
- 90-100: Production-ready, excellent quality
- 80-89: Good quality, minor improvements needed
- 70-79: Acceptable, some refactoring required
- 60-69: Below standard, significant issues
- 0-59: Major problems, extensive rework needed

Analyze the code changes as provided below thoroughly and provide your assessment following this format exactly.
        
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
