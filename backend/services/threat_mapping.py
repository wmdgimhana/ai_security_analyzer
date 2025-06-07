import json
from typing import List, Dict, Any
from langchain_groq import ChatGroq

from models import MITREAttackTechnique, OWASPVulnerability, FrameworkMapping, ThreatDetection
from config import settings

class ThreatMappingService:
    def __init__(self):
        if not settings.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in environment variables")
        
        self.ai = ChatGroq(
            groq_api_key=settings.GROQ_API_KEY,
            model_name=settings.MODEL_NAME,
            temperature=0.1
        )
        
        # Load MITRE ATT&CK and OWASP Top 10 reference data
        self.mitre_data = self._load_mitre_data()
        self.owasp_data = self._load_owasp_data()
    
    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK reference data"""
        # In a real implementation, you might load this from a file or database
        # This is a simplified version with a few common techniques
        return {
            "T1110": {
                "name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to exploit vulnerabilities in public-facing applications to gain access to systems.",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "url": "https://attack.mitre.org/techniques/T1059/"
            },
            "T1046": {
                "name": "Network Service Scanning",
                "description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to exploitation.",
                "url": "https://attack.mitre.org/techniques/T1046/"
            },
            "T1133": {
                "name": "External Remote Services",
                "description": "Adversaries may leverage external remote services as a point of initial access into your network.",
                "url": "https://attack.mitre.org/techniques/T1133/"
            }
        }
    
    def _load_owasp_data(self) -> Dict[str, Any]:
        """Load OWASP Top 10 reference data"""
        # Simplified version with a few common vulnerabilities
        return {
            "A01:2021": {
                "name": "Broken Access Control",
                "description": "Access control enforces policy such that users cannot act outside of their intended permissions.",
                "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            },
            "A03:2021": {
                "name": "Injection",
                "description": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
                "url": "https://owasp.org/Top10/A03_2021-Injection/"
            },
            "A05:2021": {
                "name": "Security Misconfiguration",
                "description": "Security misconfiguration is the most commonly seen issue, often resulting from insecure default configurations or incomplete configurations.",
                "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            },
            "A07:2021": {
                "name": "Identification and Authentication Failures",
                "description": "Authentication failures can allow attackers to assume other users' identities.",
                "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            }
        }
    
    def map_threats_to_frameworks(self, threats: List[ThreatDetection], log_sample: str) -> FrameworkMapping:
        """Map detected threats to MITRE ATT&CK and OWASP Top 10 frameworks"""
        if not threats:
            return FrameworkMapping(
                mitre_techniques=[],
                owasp_vulnerabilities=[]
            )
        
        # Prepare threat information for AI analysis
        threat_info = "\n".join([f"- {t.type} (Severity: {t.severity}): {t.description}" for t in threats])
        
        prompt = f"""
You are a cybersecurity threat analyst. Given the following web server log entries, identify possible attack patterns, then map them to the appropriate MITRE ATT&CK techniques and OWASP Top 10 vulnerabilities.

LOG SAMPLE:
{log_sample[:2000]}

Instructions:
1. Analyze each line to detect attacks (e.g., SQL injection, file inclusion, brute force).
2. If a known attack is found, map it to:
    - MITRE ATT&CK technique ID (like T1110)
    - OWASP Top 10 vulnerability ID (like A03:2021)
3. For each mapping, provide:
    - ID, name, severity, and confidence score (0.0–1.0)

Output JSON structure:
{{
    "mitre_techniques": [
        {{
            "technique_id": "T1110",
            "name": "Brute Force",
            "confidence": 0.85,
            "severity": "HIGH"
        }}
    ],
    "owasp_vulnerabilities": [
        {{
            "owasp_id": "A07:2021",
            "name": "Identification and Authentication Failures",
            "confidence": 0.9,
            "severity": "HIGH"
        }}
    ]
}}

Only include entries with high certainty based on log patterns.
"""

        
        try:
            response = self.ai.invoke(prompt)
            mapping_data = self._parse_mapping_response(response.content)
            
            # Enhance with full descriptions and URLs from reference data
            mitre_techniques = []
            for technique in mapping_data.get("mitre_techniques", []):
                technique_id = technique.get("technique_id")
                if technique_id in self.mitre_data:
                    reference = self.mitre_data[technique_id]
                    mitre_techniques.append(MITREAttackTechnique(
                        technique_id=technique_id,
                        name=technique.get("name", reference["name"]),
                        description=reference["description"],
                        url=reference["url"],
                        severity=technique.get("severity", "MEDIUM"),
                        confidence=technique.get("confidence", 0.5)
                    ))
            
            owasp_vulnerabilities = []
            for vuln in mapping_data.get("owasp_vulnerabilities", []):
                owasp_id = vuln.get("owasp_id")
                if owasp_id in self.owasp_data:
                    reference = self.owasp_data[owasp_id]
                    owasp_vulnerabilities.append(OWASPVulnerability(
                        owasp_id=owasp_id,
                        name=vuln.get("name", reference["name"]),
                        description=reference["description"],
                        url=reference["url"],
                        severity=vuln.get("severity", "MEDIUM"),
                        confidence=vuln.get("confidence", 0.5)
                    ))
            
            return FrameworkMapping(
                mitre_techniques=mitre_techniques,
                owasp_vulnerabilities=owasp_vulnerabilities
            )
            
        except Exception as e:
            print(f"Error mapping threats to frameworks: {str(e)}")
            return FrameworkMapping(
                mitre_techniques=[],
                owasp_vulnerabilities=[]
            )
    
    def _parse_mapping_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response for framework mapping"""
        try:
            # Clean and extract JSON
            response_text = response_text.strip()
            
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_content = response_text[json_start:json_end]
                return json.loads(json_content)
            
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse mapping response as JSON: {e}")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
        except Exception as e:
            print(f"Error parsing mapping response: {e}")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}