#!/usr/bin/env python3
"""
Automated Code Reviewer for GitHub Actions
Uses Mistral AI via Ollama to analyze code changes and provide scores.
"""

import difflib
import subprocess
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Optional

class CodeReviewer:
    """Main class for automated code review functionality"""
    
    def __init__(self, threshold: int = 80):
        self.threshold = threshold
        self.review_result = ""
        self.score = 0
        
    def get_file_content(self, file_path: str) -> List[str]:
        """Read and return the content of a file as lines"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.readlines()
        except FileNotFoundError:
            print(f"Warning: File not found: {file_path}")
            return []
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            return []

    def get_main_branch_content(self, file_path: str) -> List[str]:
        """Get file content from main branch for comparison"""
        try:
            result = subprocess.run(
                ['git', 'show', f'origin/main:{file_path}'],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                return result.stdout.splitlines(keepends=True)
            else:
                print(f"File {file_path} not found in main branch (new file)")
                return []
                
        except Exception as e:
            print(f"Error getting main branch content for {file_path}: {str(e)}")
            return []

    def generate_diff_for_files(self, changed_files: List[str]) -> str:
        """Generate unified diffs for all changed Python files"""
        diffs = []
        
        for file_path in changed_files:
            if not file_path.endswith('.py'):
                continue
                
            try:
                # Get main branch version
                main_lines = self.get_main_branch_content(file_path)
                
                # Get current version
                current_lines = self.get_file_content(file_path)
                
                if not current_lines:
                    continue
                
                # Generate diff
                diff = difflib.unified_diff(
                    main_lines,
                    current_lines,
                    fromfile=f'a/{file_path}',
                    tofile=f'b/{file_path}',
                    lineterm=''
                )
                
                diff_content = '\n'.join(diff)
                if diff_content.strip():
                    diffs.append(f"File: {file_path}\n{diff_content}")
                    
            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
                continue
        
        return '\n\n'.join(diffs)

    def create_review_prompt(self, diff_content: str) -> str:
        """Create the prompt for Mistral AI analysis"""
        return f"""Please review the following code changes and provide a comprehensive analysis.

Your review should include:
1. **Detailed Analysis**: What changes were made and their impact
2. **Code Quality**: Assessment of coding standards, best practices, and maintainability
3. **Security & Safety**: Any potential security issues or unsafe practices
4. **Functionality**: Whether new features work correctly and existing functionality is preserved
5. **Documentation**: Quality of comments, docstrings, and code readability

**Scoring Criteria (Total: 100 points):**
- Code quality and best practices (30 points)
- New features and functionality (25 points)  
- Error handling and robustness (25 points)
- Documentation and readability (20 points)

**IMPORTANT**: End your response with "SCORE: X" where X is your numerical score out of 100.

**Code Changes to Review:**
```diff
{diff_content}
```

Please provide your detailed analysis and final score."""

    def analyze_with_mistral(self, diff_content: str) -> Tuple[str, int]:
        """Send the diff to Mistral for analysis using Ollama"""
        if not diff_content.strip():
            return "No significant changes found to review.", 85
            
        prompt = self.create_review_prompt(diff_content)
        
        try:
            print("🤖 Analyzing code changes with Mistral AI...")
            result = subprocess.run(
                ['ollama', 'run', 'mistral', prompt],
                capture_output=True,
                text=True,
                check=True,
                timeout=300  # 5 minute timeout
            )
            
            response = result.stdout.strip()
            
            if not response:
                return "Empty response from Mistral AI", 50
            
            # Extract score from response
            score = self.extract_score(response)
            
            return response, score
            
        except subprocess.TimeoutExpired:
            return "⏰ Analysis timed out (>5 minutes). Please try with smaller changes.", 50
        except subprocess.CalledProcessError as e:
            error_msg = f"❌ Error running Mistral AI: {str(e)}"
            if e.stderr:
                error_msg += f"\nError output: {e.stderr}"
            return error_msg, 50
        except FileNotFoundError:
            return "❌ Ollama not found. Please ensure Ollama is installed and running.", 0
        except Exception as e:
            return f"❌ Unexpected error during analysis: {str(e)}", 50

    def extract_score(self, response: str) -> int:
        """Extract numerical score from AI response"""
        # Look for "SCORE: X" pattern (case insensitive)
        score_match = re.search(r'SCORE:\s*(\d+)', response, re.IGNORECASE)
        if score_match:
            return int(score_match.group(1))
        
        # Fallback: look for "X/100" or "X out of 100" patterns
        fallback_patterns = [
            r'(\d+)/100',
            r'(\d+)\s+out\s+of\s+100',
            r'score\s*:\s*(\d+)',
            r'rating\s*:\s*(\d+)'
        ]
        
        for pattern in fallback_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                score = int(match.group(1))
                if 0 <= score <= 100:
                    return score
        
        # Last resort: find any reasonable number in the response
        numbers = re.findall(r'\b(\d{1,3})\b', response)
        for num_str in reversed(numbers):  # Check from end first
            num = int(num_str)
            if 0 <= num <= 100:
                return num
        
        # Default score if nothing found
        print("⚠️  Could not extract score from AI response, using default score of 70")
        return 70

    def save_results(self, review_result: str, score: int):
        """Save review results to files for GitHub Actions"""
        try:
            with open('review_result.txt', 'w', encoding='utf-8') as f:
                f.write(review_result)
            
            with open('review_score.txt', 'w', encoding='utf-8') as f:
                f.write(str(score))
                
            print(f"✅ Results saved - Score: {score}/100")
            
        except Exception as e:
            print(f"❌ Error saving results: {str(e)}")

    def set_github_outputs(self, score: int):
        """Set outputs for GitHub Actions"""
        passed = score >= self.threshold
        
        # GitHub Actions output format
        print(f"::set-output name=score::{score}")
        print(f"::set-output name=passed::{'true' if passed else 'false'}")
        
        # Also set environment variables for other steps
        with open(os.environ.get('GITHUB_ENV', '/dev/null'), 'a') as f:
            f.write(f"REVIEW_SCORE={score}\n")
            f.write(f"REVIEW_PASSED={'true' if passed else 'false'}\n")

    def run_review(self) -> bool:
        """Main method to run the code review process"""
        print("🔍 Starting Automated Code Review")
        print("=" * 50)
        
        # Get changed files from environment
        changed_files_str = os.environ.get('CHANGED_FILES', '')
        if not changed_files_str:
            print("ℹ️  No changed files found")
            self.save_results("No changes to review", 85)
            self.set_github_outputs(85)
            return True
        
        changed_files = [f.strip() for f in changed_files_str.split() if f.strip()]
        python_files = [f for f in changed_files if f.endswith('.py')]
        
        print(f"📁 Changed files: {len(changed_files)}")
        print(f"🐍 Python files: {len(python_files)}")
        
        if not python_files:
            print("ℹ️  No Python files changed")
            self.save_results("No Python files changed", 85)
            self.set_github_outputs(85)
            return True
        
        # Generate diff for changed files
        print("📊 Generating diffs...")
        diff_content = self.generate_diff_for_files(changed_files)
        
        if not diff_content.strip():
            print("ℹ️  No significant changes found")
            self.save_results("No significant changes found", 85)
            self.set_github_outputs(85)
            return True
        
        # Analyze changes with AI
        review_result, score = self.analyze_with_mistral(diff_content)
        
        # Display results
        print("\n📋 Code Review Results:")
        print("=" * 50)
        print(review_result)
        print("=" * 50)
        print(f"🎯 Final Score: {score}/100")
        print(f"🚦 Status: {'✅ PASSED' if score >= self.threshold else '❌ FAILED'}")
        print(f"📊 Threshold: {self.threshold}/100")
        
        # Save results
        self.save_results(review_result, score)
        self.set_github_outputs(score)
        
        return score >= self.threshold

def main():
    """Main entry point"""
    try:
        # Get threshold from environment or use default
        threshold = int(os.environ.get('REVIEW_THRESHOLD', '80'))
        
        # Create and run reviewer
        reviewer = CodeReviewer(threshold=threshold)
        success = reviewer.run_review()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n⏹️  Review cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"💥 Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
