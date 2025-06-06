import json
from typing import List
from langchain_groq import ChatGroq
from models import ThreatDetection
from config import settings

class LogAnalyzerService:
    def __init__(self):
        if not settings.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in environment variables")
        
        self.ai = ChatGroq(
            groq_api_key=settings.GROQ_API_KEY,
            model_name=settings.MODEL_NAME,
            temperature=0.1  # Lower temperature for more consistent analysis
        )

    def detect_threats(self, log_text: str) -> List[ThreatDetection]:
        """Use AI to detect various types of security threats in log text"""
        try:
          
            max_chunk_size = 4000 
            if len(log_text) > max_chunk_size:
                log_text = log_text[:max_chunk_size]
            
            prompt = f"""
You are a cybersecurity expert tasked with analyzing server logs to detect potential security threats.

Analyze the following LOG DATA:
{log_text}

Identify and categorize any threats found. For each threat, return:
- "type": One of [BRUTE_FORCE, SQL_INJECTION, XSS_ATTEMPT, DIRECTORY_TRAVERSAL, SSRF, UNAUTHORIZED_ACCESS, ADMIN_PROBING, SUSPICIOUS_AGENT, DDoS_ATTACK, MALWARE_DOWNLOAD, PORT_SCANNING, COMMAND_INJECTION]
- "severity": One of [LOW, MEDIUM, HIGH, CRITICAL]
- "count": Number of occurrences
- "description": Brief description of the threat activity

Return ONLY a JSON array. If no threats are found, return an empty array: []
Example format:
[
  {{
    "type": "SQL_INJECTION",
    "severity": "HIGH",
    "count": 2,
    "description": "Detected use of SQL injection patterns on /login and /search endpoints"
  }}
]
"""
            
            response = self.ai.invoke(prompt)
            threats_data = self._parse_ai_response(response.content)
            
          
            threats = []
            for threat_data in threats_data:
                threats.append(ThreatDetection(
                    type=threat_data.get('type', 'UNKNOWN'),
                    severity=threat_data.get('severity', 'LOW'),
                    count=threat_data.get('count', 1),
                    description=threat_data.get('description', 'No description available')
                ))
            
            return threats
            
        except Exception as e:
            # Fallback: return a generic threat if AI analysis fails
            print(f"AI threat detection failed: {str(e)}")
            return [ThreatDetection(
                type="ANALYSIS_ERROR",
                severity="LOW",
                count=1,
                description=f"AI threat detection failed: {str(e)}"
            )]

    def get_ai_analysis(self, log_sample: str) -> str:
        """Get comprehensive AI analysis of the log sample"""
        try:
            prompt = f"""
            You are a senior cybersecurity analyst reviewing web server logs.

            Analyze the following LOG DATA:
            {log_sample}

            Return a full analysis with these sections:

            1. Executive Summary: One-paragraph summary of the overall security posture
            2. Threat Analysis: Describe all threats or anomalies found (with IPs, endpoints, and behaviors)
            3. Risk Assessment: Risk level [LOW, MEDIUM, HIGH, CRITICAL] and explanation
            4. Attack Patterns: Identify coordinated attacks, scanning attempts, brute-force patterns, etc.
            5. Recommendations: Clear and specific actions to reduce risk
            6. Monitoring Suggestions: What to monitor going forward (e.g., IPs, URIs, agents)

            Be specific. Use bullet points if needed. Do not include generic advice.
            """
            
            response = self.ai.invoke(prompt)
            return response.content
            
        except Exception as e:
            return f"""
            **AI Analysis Error**
            
            Unable to complete AI analysis due to: {str(e)}
            
            **Basic Log Information:**
            - Total log size: {len(log_sample)} characters
            - Estimated lines: {len(log_sample.splitlines())}
            
            **Recommendation:** Please check your API configuration and try again.
            """

    def calculate_risk_level(self, threats: List[ThreatDetection]) -> str:
        """Calculate overall risk level based on AI-detected threats"""
        if not threats:
            return "LOW"
        
        # Count threats by severity
        critical_count = sum(1 for t in threats if t.severity == "CRITICAL")
        high_count = sum(1 for t in threats if t.severity == "HIGH")
        medium_count = sum(1 for t in threats if t.severity == "MEDIUM")
        low_count = sum(1 for t in threats if t.severity == "LOW")
        
        # Calculate total threat score
        threat_score = (critical_count * 4) + (high_count * 3) + (medium_count * 2) + (low_count * 1)
        
        # Determine overall risk level
        if critical_count > 0 or threat_score >= 10:
            return "CRITICAL"
        elif high_count >= 2 or threat_score >= 6:
            return "HIGH"
        elif high_count >= 1 or medium_count >= 2 or threat_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def _parse_ai_response(self, response_text: str) -> List[dict]:
        """Parse AI response and extract threat data"""
        try:
            # Clean the response text
            response_text = response_text.strip()
            
            # Try to find JSON content
            if response_text.startswith('[') and response_text.endswith(']'):
                return json.loads(response_text)
            
            # Look for JSON block in the response
            json_start = response_text.find('[')
            json_end = response_text.rfind(']') + 1
            
            if json_start != -1 and json_end != -1:
                json_content = response_text[json_start:json_end]
                return json.loads(json_content)
            
            # If no valid JSON found, return empty list
            return []
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse AI response as JSON: {e}")
            print(f"Response was: {response_text}")
            return []
        except Exception as e:
            print(f"Error parsing AI response: {e}")
            return []

    def analyze_log_patterns(self, log_text: str) -> dict:
        """Use AI to identify suspicious patterns and anomalies"""
        try:
            prompt = f"""
            Analyze the following server logs for suspicious patterns, anomalies, and potential coordinated attacks.

            LOG DATA:
            {log_text}

            Focus on identifying:
            1. Unusual traffic patterns
            2. Suspicious IP addresses and their behavior
            3. Time-based attack patterns
            4. Coordinated multi-stage attacks
            5. Anomalous user agents or request patterns
            6. Geographic anomalies in access patterns

            Return your analysis as a JSON object with this structure:
            {{
                "suspicious_ips": ["list of suspicious IP addresses"],
                "attack_timeline": "description of when attacks occurred",
                "coordinated_attacks": "evidence of coordinated attacks",
                "anomalies": ["list of unusual patterns found"],
                "geographic_concerns": "any geographic red flags",
                "recommendations": ["specific recommendations based on patterns"]
            }}
            """
            
            response = self.ai.invoke(prompt)
            return self._parse_pattern_response(response.content)
            
        except Exception as e:
            return {
                "error": f"Pattern analysis failed: {str(e)}",
                "suspicious_ips": [],
                "attack_timeline": "Analysis unavailable",
                "coordinated_attacks": "Analysis unavailable", 
                "anomalies": [],
                "geographic_concerns": "Analysis unavailable",
                "recommendations": ["Check AI service configuration"]
            }

    def _parse_pattern_response(self, response_text: str) -> dict:
        """Parse AI pattern analysis response"""
        try:
            # Clean and extract JSON
            response_text = response_text.strip()
            
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_content = response_text[json_start:json_end]
                return json.loads(json_content)
            
            return {"error": "No valid JSON found in response"}
            
        except Exception as e:
            return {"error": f"Failed to parse pattern response: {str(e)}"}