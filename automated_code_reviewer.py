#!/usr/bin/env python3
"""
Simplified Code Reviewer - Check differences and evaluate with Ollama
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
You are an expert code reviewer. Analyze the following code changes and provide a comprehensive review with dimensional scoring.

SCORING FRAMEWORK:
Your analysis must include scores for each dimension with confidence levels and detailed reasoning.

1. CODE QUALITY (25 points):
   - Readability: Clear variable names, proper formatting, logical structure
   - Efficiency: Optimal algorithms, minimal complexity, resource usage
   - Standards: Follows language conventions, consistent style
   - Score Range: 0-25 (Excellent: 23-25, Good: 18-22, Fair: 13-17, Poor: 0-12)

2. SECURITY (25 points):
   - Vulnerabilities: SQL injection, XSS, authentication flaws
   - Data Protection: Proper encryption, secure data handling
   - Access Control: Authorization, input validation, sanitization
   - Score Range: 0-25 (Secure: 23-25, Minor concerns: 18-22, Moderate risk: 13-17, High risk: 0-12)

3. FUNCTIONALITY (20 points):
   - Correctness: Logic accuracy, expected behavior
   - Error Handling: Proper exception management, graceful failures
   - Edge Cases: Boundary conditions, null checks, validation
   - Score Range: 0-20 (Robust: 18-20, Good: 14-17, Fair: 10-13, Poor: 0-9)

4. MAINTAINABILITY (15 points):
   - Modularity: Proper separation of concerns, reusable components
   - Complexity: Manageable cyclomatic complexity, clear dependencies
   - Extensibility: Easy to modify and extend
   - Score Range: 0-15 (Excellent: 14-15, Good: 11-13, Fair: 8-10, Poor: 0-7)

5. DOCUMENTATION (10 points):
   - Code Comments: Complex logic explained, purpose clarified
   - Function Documentation: Parameters, return values, behavior
   - API Documentation: Public interfaces documented
   - Score Range: 0-10 (Well documented: 9-10, Adequate: 7-8, Minimal: 4-6, Poor: 0-3)

6. PERFORMANCE (3 points):
   - Efficiency: Time and space complexity considerations
   - Resource Usage: Memory leaks, unnecessary allocations
   - Score Range: 0-3 (Optimal: 3, Good: 2, Acceptable: 1, Poor: 0)

7. TESTING (2 points):
   - Test Coverage: Adequate test cases
   - Test Quality: Meaningful assertions, edge case coverage
   - Score Range: 0-2 (Comprehensive: 2, Basic: 1, None: 0)

CONFIDENCE LEVELS:
For each dimension, provide a confidence level (0.0-1.0):
- 0.9-1.0: Very confident in assessment
- 0.7-0.9: Confident with minor uncertainty
- 0.5-0.7: Moderate confidence, some ambiguity
- 0.3-0.5: Low confidence, significant uncertainty
- 0.0-0.3: Very uncertain, needs human review

ANALYSIS PRIORITIES:
1. Security vulnerabilities (immediate attention)
2. Functional correctness (breaks system)
3. Performance bottlenecks (scalability issues)
4. Maintainability concerns (long-term impact)
5. Documentation gaps (team productivity)

CODE CHANGES:
```diff
{diff_content}
```

REQUIRED RESPONSE FORMAT:
```json
{{
  "dimension_scores": {{
    "code_quality": {{
      "score": <0-25>,
      "confidence": <0.0-1.0>,
      "reasoning": "Detailed explanation of score",
      "issues": ["Specific issue 1", "Specific issue 2"],
      "suggestions": ["Improvement 1", "Improvement 2"]
    }},
    "security": {{
      "score": <0-25>,
      "confidence": <0.0-1.0>,
      "reasoning": "Security analysis explanation",
      "issues": ["Security issue 1", "Security issue 2"],
      "suggestions": ["Security improvement 1", "Security improvement 2"]
    }},
    "functionality": {{
      "score": <0-20>,
      "confidence": <0.0-1.0>,
      "reasoning": "Functionality assessment",
      "issues": ["Functional issue 1"],
      "suggestions": ["Functional improvement 1"]
    }},
    "maintainability": {{
      "score": <0-15>,
      "confidence": <0.0-1.0>,
      "reasoning": "Maintainability analysis",
      "issues": ["Maintainability issue 1"],
      "suggestions": ["Maintainability improvement 1"]
    }},
    "documentation": {{
      "score": <0-10>,
      "confidence": <0.0-1.0>,
      "reasoning": "Documentation assessment",
      "issues": ["Documentation gap 1"],
      "suggestions": ["Documentation improvement 1"]
    }},
    "performance": {{
      "score": <0-3>,
      "confidence": <0.0-1.0>,
      "reasoning": "Performance analysis",
      "issues": ["Performance issue 1"],
      "suggestions": ["Performance improvement 1"]
    }},
    "testing": {{
      "score": <0-2>,
      "confidence": <0.0-1.0>,
      "reasoning": "Testing assessment",
      "issues": ["Testing gap 1"],
      "suggestions": ["Testing improvement 1"]
    }}
  }},
  "overall_assessment": {{
    "critical_issues": ["Most critical issues requiring immediate attention"],
    "minor_issues": ["Minor issues that can be addressed later"],
    "good_practices": ["Positive aspects of the code"],
    "review_summary": "Overall assessment of the changes"
  }}
}}
```

IMPORTANT: 
- Be specific and actionable in your feedback
- Prioritize security and functionality issues
- Consider the impact on the overall system
- Provide concrete suggestions for improvement
- If total score < 70, provide detailed improvement plan
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
        end_time = time.time()
        elapsed = end_time - start_time
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        print(f"Response generated in {minutes} min {seconds} sec")
        
        response = result.stdout.strip()
        # score = extract_score(response)
        return response
        
    except subprocess.TimeoutExpired:
        return "Analysis timed out", 50
    # except FileNotFoundError:
    #     return "Ollama not found", 0
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
        return _parse_fallback_response(response)
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return _parse_fallback_response(response)
    except Exception as e:
        print(f"Unexpected parsing error: {e}")
        return _create_default_response()
    
def _parse_fallback_response(response: str) -> Dict:
    """Fallback parser for non-JSON responses"""
    # Extract scores using regex patterns
    scores = {}
    
    # Pattern to match dimension scores in markdown-style LLM output
    # Looks for: "#### Code Quality (0/25)\n- **Score**: 10"
    dimension_patterns = {
        'code_quality': r'####\s*Code Quality.*?\n- \*\*Score\*\*:\s*(\d+)',
        'security': r'####\s*Security.*?\n- \*\*Score\*\*:\s*(\d+)',
        'functionality': r'####\s*Functionality.*?\n- \*\*Score\*\*:\s*(\d+)',
        'maintainability': r'####\s*Maintainability.*?\n- \*\*Score\*\*:\s*(\d+)',
        'documentation': r'####\s*Documentation.*?\n- \*\*Score\*\*:\s*(\d+)',
        'performance': r'####\s*Performance.*?\n- \*\*Score\*\*:\s*(\d+)',
        'testing': r'####\s*Testing.*?\n- \*\*Score\*\*:\s*(\d+)',
    }

    for dimension, pattern in dimension_patterns.items():
        match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
        if match:
            scores[dimension] = {
                'score': int(match.group(1)),
                'confidence': 0.7,  # Default confidence
                'reasoning': f"Score extracted from fallback parsing",
                'issues': [],
                'suggestions': []
            }
    # Extract issues and suggestions
    critical_issues = _extract_list_items(response, r'critical[_\s]issues?[:\s]*([^\n]+)')
    minor_issues = _extract_list_items(response, r'minor[_\s]issues?[:\s]*([^\n]+)')
    good_practices = _extract_list_items(response, r'good[_\s]practices?[:\s]*([^\n]+)')
    
    return {
        'dimension_scores': scores,
        'overall_assessment': {
            'critical_issues': critical_issues,
            'minor_issues': minor_issues,
            'good_practices': good_practices,
            'review_summary': "Fallback parsing used due to response format issues"
        }
    }

def _calculate_overall_score(parsed_response: Dict) -> Tuple[int, float]:
    """Calculate weighted overall score and confidence"""
    total_score = 0
    weighted_confidence = 0
    total_weight = 0
    
    dimension_scores = parsed_response.get('dimension_scores', {})
    
    dimension_weights = {
        'code_quality': 0.25,
        'security': 0.25,
        'functionality': 0.20,
        'maintainability': 0.15,
        'documentation': 0.10,
        'performance': 0.03,
        'testing': 0.02
    }

    for dimension, weight in dimension_weights.items():
        if dimension in dimension_scores:
            score_data = dimension_scores[dimension]
            score = score_data.get('score', 0)
            confidence = score_data.get('confidence', 0.5)
            
            # # Convert to percentage based on max scores
            # max_scores = {
            #     'code_quality': 25, 'security': 25, 'functionality': 20,
            #     'maintainability': 15, 'documentation': 10, 'performance': 3, 'testing': 2
            # }
            
            total_score += score
            weighted_confidence += confidence * weight
            total_weight += weight
    
    overall_score = int(total_score)
    overall_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.5
    
    return overall_score, overall_confidence

def _extract_list_items(text: str, pattern: str) -> List[str]:
    """Extract list items from text using regex"""
    matches = re.findall(pattern, text, re.IGNORECASE)
    return [item.strip() for item in matches if item.strip()]

def _create_default_response() -> Dict:
    """Create default response when parsing fails"""
    return {
        'dimension_scores': {
            'code_quality': {'score': 15, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'security': {'score': 15, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'functionality': {'score': 12, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'maintainability': {'score': 9, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'documentation': {'score': 6, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'performance': {'score': 2, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []},
            'testing': {'score': 1, 'confidence': 0.3, 'reasoning': 'Default score due to parsing error', 'issues': [], 'suggestions': []}
        },
        'overall_assessment': {
            'critical_issues': ['Response parsing failed - requires human review'],
            'minor_issues': [],
            'good_practices': [],
            'review_summary': 'Unable to parse LLM response properly'
        }
    }

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
    # Calculate overall score and confidence
    overall_score, overall_confidence = _calculate_overall_score(parsed_response)
    
    # Display results
    print("\nReview Results:")
    print("=" * 50)
    print(response)
    print("=" * 50)
    print(f"Score: {overall_score}/100")
    print("=" * 50)
    print(f"Confidence: {overall_confidence:.2f}")
    
    # Store results in variables for further use
    return {
        'diff': diff_content,
        'review': response,
        'score': overall_score,
        'confidence': overall_confidence
    }

if __name__ == '__main__':
    results = main()
