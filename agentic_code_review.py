import json
import logging
import subprocess
from typing import Dict, List, Any, Optional, TypedDict
from dataclasses import dataclass, asdict
import asyncio
import aiohttp
from enum import Enum
import re
import os
import sys

# LangGraph imports
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_core.pydantic_v1 import BaseModel, Field
# Updated import to fix deprecation warning
try:
    from langchain_ollama import OllamaLLM
except ImportError:
    from langchain_community.llms import Ollama as OllamaLLM
    print("Warning: Using deprecated Ollama import. Install langchain-ollama: pip install -U langchain-ollama")

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate

os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', line_buffering=True)
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8', line_buffering=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReviewState(TypedDict):
    """State passed between nodes in the review graph"""
    code_diff: str
    current_analysis: str
    code_quality_result: Optional[Dict]
    security_result: Optional[Dict]
    functionality_result: Optional[Dict]
    maintainability_result: Optional[Dict]
    documentation_result: Optional[Dict]
    performance_result: Optional[Dict]
    testing_result: Optional[Dict]
    final_result: Optional[Dict]
    messages: List[BaseMessage]
    current_step: str
    error_count: int

class RiskLevel(Enum):
    """Risk levels for code review"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class CodeReviewScore:
    """Individual dimension score"""
    score: int
    confidence: float
    reasoning: str
    issues: List[str]
    suggestions: List[str]

@dataclass
class OverallAssessment:
    """Overall code review assessment"""
    total_score: int
    risk_level: str
    critical_issues: List[str]
    minor_issues: List[str]
    good_practices: List[str]
    review_summary: str
    recommendation: str

class OllamaConfig:
    """Configuration for Ollama models"""
    def __init__(self, 
                 model: str = "qwen2.5-coder:3b",
                 base_url: str = "http://localhost:11434",
                 temperature: float = 0.1,
                 top_p: float = 0.9,
                 max_tokens: int = 4096):
        self.model = model
        self.base_url = base_url
        self.temperature = temperature
        self.top_p = top_p
        self.max_tokens = max_tokens

class GitOperations:
    def get_code_diff(branch_name="autotest-review") -> str:
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

class LangGraphCodeReviewer:
    """LangGraph-based code review system with Ollama integration"""
    
    def __init__(self, ollama_config: Optional[OllamaConfig] = None):
        self.ollama_config = ollama_config or OllamaConfig()
        self.llm = self._setup_ollama()
        self.graph = self._build_review_graph()
        self.json_parser = JsonOutputParser()
        
    def _setup_ollama(self) -> OllamaLLM:
        """Setup Ollama LLM with configuration"""
        try:
            llm = OllamaLLM(
                model=self.ollama_config.model,
                base_url=self.ollama_config.base_url,
                temperature=self.ollama_config.temperature,
                # Note: some parameters might vary between versions
                num_predict=self.ollama_config.max_tokens,
                verbose=True
            )
            
            # Test connection
            test_response = llm.invoke("Test connection")
            logger.info(f"✅ Ollama connection successful with model: {self.ollama_config.model}")
            return llm
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Ollama: {e}")
            logger.info("Make sure Ollama is running with: ollama serve")
            logger.info(f"And model is pulled with: ollama pull {self.ollama_config.model}")
            raise

    def _create_analysis_prompt(self, dimension: str, criteria: str, max_score: int) -> ChatPromptTemplate:
        """Create standardized prompt for each analysis dimension"""
        template = f"""You are an expert code reviewer specializing in {dimension} analysis.

ANALYSIS TASK: Analyze the code changes for {dimension} and provide a structured assessment.

SCORING CRITERIA ({dimension.upper()} - 0-{max_score} points):
{criteria}

CONFIDENCE LEVELS:
- 0.9-1.0: Very confident in assessment
- 0.7-0.9: Confident with minor uncertainty  
- 0.5-0.7: Moderate confidence, some ambiguity
- 0.3-0.5: Low confidence, significant uncertainty
- 0.0-0.3: Very uncertain, needs human review

CODE CHANGES:
```diff
{{code_diff}}
```

CRITICAL: You must respond with ONLY a valid JSON object. No explanations, no markdown, no additional text.

Required JSON format:
{{{{
  "score": <integer 0-{max_score}>,
  "confidence": <float 0.0-1.0>,
  "reasoning": "Detailed explanation of score focusing on {dimension}",
  "issues": ["Specific issue 1", "Specific issue 2"],
  "suggestions": ["Improvement 1", "Improvement 2"]
}}}}

IMPORTANT: 
- Return ONLY valid JSON, no other text
- Be specific and actionable in feedback
- Focus exclusively on {dimension} aspects
- Provide concrete examples from the code
- Ensure all JSON strings are properly escaped
"""
        return ChatPromptTemplate.from_template(template)

    def _build_review_graph(self) -> StateGraph:
        """Build the LangGraph workflow for code review"""
        
        # Create the state graph
        workflow = StateGraph(ReviewState)
        
        # Add nodes for each review dimension
        workflow.add_node("start", self._start_review)
        workflow.add_node("code_quality", self._analyze_code_quality)
        workflow.add_node("security", self._analyze_security)
        workflow.add_node("functionality", self._analyze_functionality)
        workflow.add_node("maintainability", self._analyze_maintainability)
        workflow.add_node("documentation", self._analyze_documentation)
        workflow.add_node("performance", self._analyze_performance)
        workflow.add_node("testing", self._analyze_testing)
        workflow.add_node("final_assessment", self._create_final_assessment)
        workflow.add_node("error_handler", self._handle_error)
        
        # Define the workflow edges (sequential processing)
        workflow.set_entry_point("start")
        workflow.add_edge("start", "code_quality")
        workflow.add_edge("code_quality", "security")
        workflow.add_edge("security", "functionality")
        workflow.add_edge("functionality", "maintainability")
        workflow.add_edge("maintainability", "documentation")
        workflow.add_edge("documentation", "performance")
        workflow.add_edge("performance", "testing")
        workflow.add_edge("testing", "final_assessment")
        workflow.add_edge("final_assessment", END)
        workflow.add_edge("error_handler", END)
        
        return workflow.compile()

    def _start_review(self, state: ReviewState) -> ReviewState:
        """Initialize the review process"""
        logger.info("🚀 Starting code review process...")
        state["current_step"] = "initialized"
        state["error_count"] = 0
        state["messages"] = [HumanMessage(content=f"Starting review of code diff: {len(state['code_diff'])} characters")]
        return state

    def _analyze_code_quality(self, state: ReviewState) -> ReviewState:
        """Analyze code quality dimension"""
        logger.info("🔍 Analyzing code quality...")
        
        criteria = """
        - Readability: Clear variable names, proper formatting, logical structure
        - Efficiency: Optimal algorithms, minimal complexity, resource usage
        - Standards: Follows language conventions, consistent style
        """
        
        try:
            prompt = self._create_analysis_prompt("code quality", criteria, 25)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            logger.debug(f"Raw response: {response[:200]}...")
            
            result = self._extract_and_parse_json(response, "code quality")
            state["code_quality_result"] = result
            state["current_step"] = "code_quality_complete"
            logger.info(f"✅ Code quality analysis complete - Score: {result['score']}/25")
        except Exception as e:
            logger.error(f"❌ Error in code quality analysis: {e}")
            state["error_count"] += 1
            state["code_quality_result"] = self._create_error_result("code quality", str(e))
            
        return state

    def _analyze_security(self, state: ReviewState) -> ReviewState:
        """Analyze security dimension"""
        logger.info("🔒 Analyzing security...")
        
        criteria = """
        - Vulnerabilities: SQL injection, XSS, authentication flaws, OWASP Top 10
        - Data Protection: Proper encryption, secure data handling, sensitive info exposure
        - Access Control: Authorization checks, input validation, sanitization
        """
        
        try:
            prompt = self._create_analysis_prompt("security", criteria, 25)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "security")
            state["security_result"] = result
            state["current_step"] = "security_complete"
            logger.info(f"✅ Security analysis complete - Score: {result['score']}/25")
        except Exception as e:
            logger.error(f"❌ Error in security analysis: {e}")
            state["error_count"] += 1
            state["security_result"] = self._create_error_result("security", str(e))
            
        return state

    def _analyze_functionality(self, state: ReviewState) -> ReviewState:
        """Analyze functionality dimension"""
        logger.info("⚙️ Analyzing functionality...")
        
        criteria = """
        - Correctness: Logic accuracy, expected behavior, algorithm correctness
        - Error Handling: Proper exception management, graceful failures, edge cases
        - Edge Cases: Boundary conditions, null checks, input validation
        """
        
        try:
            prompt = self._create_analysis_prompt("functionality", criteria, 20)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "functionality")
            state["functionality_result"] = result
            state["current_step"] = "functionality_complete"
            logger.info(f"✅ Functionality analysis complete - Score: {result['score']}/20")
        except Exception as e:
            logger.error(f"❌ Error in functionality analysis: {e}")
            state["error_count"] += 1
            state["functionality_result"] = self._create_error_result("functionality", str(e))
            
        return state

    def _analyze_maintainability(self, state: ReviewState) -> ReviewState:
        """Analyze maintainability dimension"""
        logger.info("🔧 Analyzing maintainability...")
        
        criteria = """
        - Modularity: Proper separation of concerns, reusable components
        - Complexity: Manageable cyclomatic complexity, clear dependencies
        - Extensibility: Easy to modify and extend, flexible design
        """
        
        try:
            prompt = self._create_analysis_prompt("maintainability", criteria, 15)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "maintainability")
            state["maintainability_result"] = result
            state["current_step"] = "maintainability_complete"
            logger.info(f"✅ Maintainability analysis complete - Score: {result['score']}/15")
        except Exception as e:
            logger.error(f"❌ Error in maintainability analysis: {e}")
            state["error_count"] += 1
            state["maintainability_result"] = self._create_error_result("maintainability", str(e))
            
        return state

    def _analyze_documentation(self, state: ReviewState) -> ReviewState:
        """Analyze documentation dimension"""
        logger.info("📚 Analyzing documentation...")
        
        criteria = """
        - Code Comments: Complex logic explained, purpose clarified
        - Function Documentation: Parameters, return values, behavior documented
        - API Documentation: Public interfaces properly documented
        """
        
        try:
            prompt = self._create_analysis_prompt("documentation", criteria, 10)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "documentation")
            state["documentation_result"] = result
            state["current_step"] = "documentation_complete"
            logger.info(f"✅ Documentation analysis complete - Score: {result['score']}/10")
        except Exception as e:
            logger.error(f"❌ Error in documentation analysis: {e}")
            state["error_count"] += 1
            state["documentation_result"] = self._create_error_result("documentation", str(e))
            
        return state

    def _analyze_performance(self, state: ReviewState) -> ReviewState:
        """Analyze performance dimension"""
        logger.info("⚡ Analyzing performance...")
        
        criteria = """
        - Efficiency: Time and space complexity considerations
        - Resource Usage: Memory leaks, unnecessary allocations, optimization opportunities
        """
        
        try:
            prompt = self._create_analysis_prompt("performance", criteria, 3)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "performance")
            state["performance_result"] = result
            state["current_step"] = "performance_complete"
            logger.info(f"✅ Performance analysis complete - Score: {result['score']}/3")
        except Exception as e:
            logger.error(f"❌ Error in performance analysis: {e}")
            state["error_count"] += 1
            state["performance_result"] = self._create_error_result("performance", str(e))
            
        return state

    def _analyze_testing(self, state: ReviewState) -> ReviewState:
        """Analyze testing dimension"""
        logger.info("🧪 Analyzing testing...")
        
        criteria = """
        - Test Coverage: Adequate test cases for the code changes
        - Test Quality: Meaningful assertions, edge case coverage, test structure
        """
        
        try:
            prompt = self._create_analysis_prompt("testing", criteria, 2)
            response = self.llm.invoke(prompt.format(code_diff=state["code_diff"]))
            result = self._extract_and_parse_json(response, "testing")
            state["testing_result"] = result
            state["current_step"] = "testing_complete"
            logger.info(f"✅ Testing analysis complete - Score: {result['score']}/2")
        except Exception as e:
            logger.error(f"❌ Error in testing analysis: {e}")
            state["error_count"] += 1
            state["testing_result"] = self._create_error_result("testing", str(e))
            
        return state

    def _create_final_assessment(self, state: ReviewState) -> ReviewState:
        """Create comprehensive final assessment"""
        logger.info("📊 Creating final assessment...")
        
        try:
            # Calculate total score (handle None values)
            total_score = 0
            for key in ["code_quality_result", "security_result", "functionality_result", 
                       "maintainability_result", "documentation_result", "performance_result", "testing_result"]:
                result = state.get(key)
                if result and isinstance(result, dict) and "score" in result:
                    total_score += result["score"]
            
            # Determine risk level
            security_score = state.get("security_result", {}).get("score", 0)
            functionality_score = state.get("functionality_result", {}).get("score", 0)
            risk_level = self._calculate_risk_level(total_score, security_score, functionality_score)
            
            # Collect all issues
            critical_issues = []
            minor_issues = []
            good_practices = []
            
            # Process results from each dimension
            for dimension, key in [
                ("code_quality", "code_quality_result"),
                ("security", "security_result"),
                ("functionality", "functionality_result"),
                ("maintainability", "maintainability_result"),
                ("documentation", "documentation_result"),
                ("performance", "performance_result"),
                ("testing", "testing_result")
            ]:
                result = state.get(key, {})
                if not result:
                    continue
                    
                score = result.get("score", 0)
                issues = result.get("issues", [])
                
                # Adjust thresholds based on dimension max scores
                max_scores = {"code_quality": 25, "security": 25, "functionality": 20, 
                             "maintainability": 15, "documentation": 10, "performance": 3, "testing": 2}
                max_score = max_scores.get(dimension, 10)
                
                if score < max_score * 0.5:  # Below 50% of max score
                    critical_issues.extend(issues)
                else:
                    minor_issues.extend(issues)
                    
                if score > max_score * 0.8:  # Above 80% of max score
                    good_practices.append(f"Good {dimension} implementation")
            
            # Generate recommendation
            recommendation = self._generate_recommendation(total_score, critical_issues, risk_level)
            
            # Create final result
            final_result = {
                "dimension_scores": {
                    "code_quality": state.get("code_quality_result", {}),
                    "security": state.get("security_result", {}),
                    "functionality": state.get("functionality_result", {}),
                    "maintainability": state.get("maintainability_result", {}),
                    "documentation": state.get("documentation_result", {}),
                    "performance": state.get("performance_result", {}),
                    "testing": state.get("testing_result", {})
                },
                "overall_assessment": {
                    "total_score": total_score,
                    "risk_level": risk_level,
                    "critical_issues": critical_issues[:10],  # Limit to top 10
                    "minor_issues": minor_issues[:15],       # Limit to top 15
                    "good_practices": good_practices,
                    "review_summary": self._generate_summary(total_score, critical_issues, risk_level),
                    "recommendation": recommendation
                }
            }
            
            state["final_result"] = final_result
            state["current_step"] = "complete"
            
            logger.info(f"✅ Final assessment complete - Total Score: {total_score}/100, Risk: {risk_level}")
            
        except Exception as e:
            logger.error(f"❌ Error in final assessment: {e}")
            state["error_count"] += 1
            state["final_result"] = {"error": f"Final assessment failed: {str(e)}"}
            
        return state

    def _extract_and_parse_json(self, response: str, dimension: str) -> Dict:
        """Improved JSON extraction and parsing with multiple fallback strategies"""
        try:
            # Strategy 1: Clean and extract JSON
            json_str = self._extract_json_from_response(response)
            return json.loads(json_str)
            
        except Exception as e1:
            logger.warning(f"Strategy 1 failed for {dimension}: {e1}")
            
            try:
                # Strategy 2: Use regex to find JSON-like structure
                pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
                matches = re.findall(pattern, response, re.DOTALL)
                
                for match in matches:
                    try:
                        return json.loads(match)
                    except:
                        continue
                        
            except Exception as e2:
                logger.warning(f"Strategy 2 failed for {dimension}: {e2}")
            
            # Strategy 3: Create fallback result
            logger.warning(f"All JSON parsing strategies failed for {dimension}, creating fallback")
            return self._create_fallback_result(response, dimension)

    def _extract_json_from_response(self, response: str) -> str:
        """Extract JSON from LLM response with improved logic"""
        response = response.strip()
        
        # Remove markdown code blocks if present
        if response.startswith("```json"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]
        if response.endswith("```"):
            response = response[:-3]
        
        response = response.strip()
        
        # Find JSON object boundaries
        brace_count = 0
        start_idx = -1
        
        for i, char in enumerate(response):
            if char == '{':
                if start_idx == -1:
                    start_idx = i
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_idx != -1:
                    return response[start_idx:i+1]
        
        # Fallback to simple approach
        start = response.find('{')
        end = response.rfind('}') + 1
        
        if start >= 0 and end > start:
            return response[start:end]
        else:
            raise ValueError(f"No valid JSON found in response: {response[:100]}...")

    def _create_fallback_result(self, response: str, dimension: str) -> Dict:
        """Create a fallback result when JSON parsing fails"""
        # Try to extract some meaningful info from the response
        score = 5  # Default middle score
        confidence = 0.3  # Low confidence
        
        # Simple heuristics to guess score
        if any(word in response.lower() for word in ["excellent", "good", "high", "strong"]):
            score = 15
            confidence = 0.5
        elif any(word in response.lower() for word in ["poor", "bad", "low", "weak", "critical"]):
            score = 2
            confidence = 0.5
        
        return {
            "score": score,
            "confidence": confidence,
            "reasoning": f"Fallback analysis for {dimension} - original parsing failed. Response: {response[:200]}...",
            "issues": [f"JSON parsing failed for {dimension} analysis"],
            "suggestions": [f"Manual review recommended for {dimension}"]
        }

    def _create_error_result(self, dimension: str, error_msg: str) -> Dict:
        """Create error result for failed analysis"""
        return {
            "score": 0,
            "confidence": 0.0,
            "reasoning": f"Analysis failed: {error_msg}",
            "issues": [f"{dimension} analysis could not be completed"],
            "suggestions": [f"Retry {dimension} analysis or review manually"]
        }

    def _calculate_risk_level(self, total_score: int, security_score: int, functionality_score: int) -> str:
        """Calculate overall risk level"""
        if security_score < 15 or functionality_score < 10 or total_score < 40:
            return RiskLevel.CRITICAL.value
        elif security_score < 20 or functionality_score < 15 or total_score < 60:
            return RiskLevel.HIGH.value
        elif total_score < 80:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value

    def _generate_recommendation(self, total_score: int, critical_issues: List[str], risk_level: str) -> str:
        """Generate final recommendation"""
        if risk_level == RiskLevel.CRITICAL.value:
            return "REJECT"
        elif risk_level == RiskLevel.HIGH.value and len(critical_issues) > 3:
            return "REJECT"
        elif risk_level in [RiskLevel.HIGH.value, RiskLevel.MEDIUM.value]:
            return "APPROVE_WITH_CHANGES"
        else:
            return "APPROVE"

    def _generate_summary(self, total_score: int, critical_issues: List[str], risk_level: str) -> str:
        """Generate review summary"""
        if risk_level == RiskLevel.CRITICAL.value:
            return f"Critical issues found requiring immediate attention. Total score: {total_score}/100. {len(critical_issues)} critical issues identified."
        elif risk_level == RiskLevel.HIGH.value:
            return f"High risk code changes with significant issues. Total score: {total_score}/100. Review and address issues before merging."
        elif risk_level == RiskLevel.MEDIUM.value:
            return f"Moderate quality code with some improvements needed. Total score: {total_score}/100. Address minor issues for better quality."
        else:
            return f"Good quality code with minimal issues. Total score: {total_score}/100. Ready for deployment with minor considerations."

    def _handle_error(self, state: ReviewState) -> ReviewState:
        """Handle errors in the review process"""
        logger.error(f"❌ Review process encountered {state['error_count']} errors")
        state["current_step"] = "error"
        return state

    def review_code(self, code_diff: str) -> Dict[str, Any]:
        """Execute the complete code review workflow"""
        try:
            logger.info("🎯 Starting LangGraph code review workflow...")
            
            # Initialize state
            initial_state: ReviewState = {
                "code_diff": code_diff,
                "current_analysis": "",
                "code_quality_result": None,
                "security_result": None,
                "functionality_result": None,
                "maintainability_result": None,
                "documentation_result": None,
                "performance_result": None,
                "testing_result": None,
                "final_result": None,
                "messages": [],
                "current_step": "starting",
                "error_count": 0
            }
            
            # Execute the workflow
            final_state = self.graph.invoke(initial_state)
            
            # More lenient error handling
            if final_state.get("error_count", 0) > 5:  # Increased threshold
                logger.warning("❌ Multiple errors in review process, but continuing with available results")
            
            return final_state.get("final_result", {"error": "No result generated"})
            
        except Exception as e:
            logger.error(f"❌ Critical error in review workflow: {e}")
            return {"error": f"Workflow execution failed: {str(e)}"}

# Usage example and configuration
def main():
    """Demonstrate the LangGraph code review system"""
    code_diff = GitOperations.get_code_diff("autotest-review")
    print(code_diff)
    # Configure Ollama (adjust model and settings as needed)
    ollama_config = OllamaConfig(
        model="qwen2.5-coder:3b",  # Fast, code-focused model
        base_url="http://localhost:11434",
        temperature=0.1,  # Low temperature for consistent analysis
        top_p=0.9,
        max_tokens=4096
    )
    
    try:
        # Initialize the reviewer
        print("🚀 Initializing LangGraph Code Reviewer with Ollama...")
        reviewer = LangGraphCodeReviewer(ollama_config)
        
        # Execute the review
        print("⏳ Executing code review workflow...")
        # review_result = reviewer.review_code(sample_diff)
        review_result = reviewer.review_code(code_diff)
        
        # Display results
        print("\n" + "="*60)
        print("🎯 LANGGRAPH CODE REVIEW RESULTS")
        print("="*60)
        
        if "error" in review_result:
            print(f"❌ Error: {review_result['error']}")
        else:
            # Pretty print results
            overall = review_result.get("overall_assessment", {})
            print(f"📊 Total Score: {overall.get('total_score', 'N/A')}/100")
            print(f"🚨 Risk Level: {overall.get('risk_level', 'N/A')}")
            print(f"✅ Recommendation: {overall.get('recommendation', 'N/A')}")
            
            print(f"\n🔍 Dimension Scores:")
            dimensions = review_result.get("dimension_scores", {})
            for dim, result in dimensions.items():
                if result:
                    print(f"  {dim.title()}: {result.get('score', 'N/A')} (conf: {result.get('confidence', 0):.2f})")
            
            print(f"\n⚠️ Critical Issues ({len(overall.get('critical_issues', []))}):")
            for issue in overall.get('critical_issues', [])[:5]:
                print(f"  • {issue}")
            
            print(f"\n📝 Summary:")
            print(f"  {overall.get('review_summary', 'No summary available')}")
        
            print("\n" + "="*60)
        
            print(review_result)
        
    except Exception as e:
        print(f"❌ Failed to initialize or run code review: {e}")
        print("\n🔧 Troubleshooting:")
        print("1. Ensure Ollama is running: `ollama serve`")
        print("2. Pull the model: `ollama pull qwen2.5-coder:3b`")
        print("3. Check if the model name is correct")
        print("4. Verify Ollama is accessible at http://localhost:11434")
        return None

if __name__ == "__main__":
    result = main()
