import json
import re
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
            },
            "T1505": {
                "name": "Server Software Component",
                "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems.",
                "url": "https://attack.mitre.org/techniques/T1505/"
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                "url": "https://attack.mitre.org/techniques/T1083/"
            }
        }
    
    def _load_owasp_data(self) -> Dict[str, Any]:
        """Load OWASP Top 10 reference data"""
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
            },
            "A06:2021": {
                "name": "Vulnerable and Outdated Components",
                "description": "Components run with the same privileges as the application itself, so flaws in any component can result in serious impact.",
                "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
            }
        }
    
    def _analyze_logs_locally(self, log_sample: str) -> Dict[str, Any]:
        """Perform local pattern analysis as fallback"""
        mitre_techniques = []
        owasp_vulnerabilities = []
        
        # SQL Injection patterns
        sql_patterns = [
            r"(?i)(union\s+select|or\s+1\s*=\s*1|'.*'=.*'|admin'--|%27|sqlmap)",
            r"(?i)(\bor\b.*\b1\b.*\b=\b.*\b1\b|'\s*or\s*'1'\s*=\s*'1)",
        ]
        
        # Command injection patterns
        cmd_patterns = [
            r"(?i)(cmd=|;.*whoami|;.*ls|;.*cat|%7C|pipe|&.*whoami)",
            r"(?i)(\|whoami|\|ls|\|cat|%7Cwhoami)"
        ]
        
        # Directory traversal patterns
        traversal_patterns = [
            r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\/etc\/passwd|\/etc\/shadow)",
            r"(?i)(\.\..*\/.*\/.*etc|file=.*\.\./)"
        ]
        
        # Brute force patterns (repeated login attempts, common attack tools)
        brute_force_patterns = [
            r"(?i)(wp-login\.php|admin.*login|login.*admin)",
            r"(?i)(nikto|dirb|gobuster|hydra)"
        ]
        
        log_lines = log_sample.split('\n')
        attack_indicators = []
        
        for line in log_lines:
            if not line.strip():
                continue
                
            # Check for SQL injection
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    attack_indicators.append("SQL_INJECTION")
                    break
            
            # Check for command injection
            for pattern in cmd_patterns:
                if re.search(pattern, line):
                    attack_indicators.append("COMMAND_INJECTION")
                    break
            
            # Check for directory traversal
            for pattern in traversal_patterns:
                if re.search(pattern, line):
                    attack_indicators.append("DIRECTORY_TRAVERSAL")
                    break
            
            # Check for brute force
            for pattern in brute_force_patterns:
                if re.search(pattern, line):
                    attack_indicators.append("BRUTE_FORCE")
                    break
        
        # Map detected attacks to frameworks
        unique_attacks = set(attack_indicators)
        
        if "SQL_INJECTION" in unique_attacks:
            mitre_techniques.append({
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "confidence": 0.9,
                "severity": "HIGH"
            })
            owasp_vulnerabilities.append({
                "owasp_id": "A03:2021",
                "name": "Injection",
                "confidence": 0.9,
                "severity": "HIGH"
            })
        
        if "COMMAND_INJECTION" in unique_attacks:
            mitre_techniques.append({
                "technique_id": "T1059",
                "name": "Command and Scripting Interpreter",
                "confidence": 0.85,
                "severity": "HIGH"
            })
            owasp_vulnerabilities.append({
                "owasp_id": "A03:2021",
                "name": "Injection",
                "confidence": 0.85,
                "severity": "HIGH"
            })
        
        if "DIRECTORY_TRAVERSAL" in unique_attacks:
            mitre_techniques.append({
                "technique_id": "T1083",
                "name": "File and Directory Discovery",
                "confidence": 0.8,
                "severity": "MEDIUM"
            })
            owasp_vulnerabilities.append({
                "owasp_id": "A01:2021",
                "name": "Broken Access Control",
                "confidence": 0.8,
                "severity": "HIGH"
            })
        
        if "BRUTE_FORCE" in unique_attacks:
            mitre_techniques.append({
                "technique_id": "T1110",
                "name": "Brute Force",
                "confidence": 0.7,
                "severity": "MEDIUM"
            })
            owasp_vulnerabilities.append({
                "owasp_id": "A07:2021",
                "name": "Identification and Authentication Failures",
                "confidence": 0.7,
                "severity": "MEDIUM"
            })
        
        return {
            "mitre_techniques": mitre_techniques,
            "owasp_vulnerabilities": owasp_vulnerabilities
        }
    
    def map_threats_to_frameworks(self, threats: List[ThreatDetection], log_sample: str) -> FrameworkMapping:
        """Map detected threats to MITRE ATT&CK and OWASP Top 10 frameworks"""
        if not log_sample.strip():
            return FrameworkMapping(
                mitre_techniques=[],
                owasp_vulnerabilities=[]
            )
        
        # First try local analysis as primary method
        print("Performing local threat analysis...")
        local_mapping = self._analyze_logs_locally(log_sample)
        
        # Also try AI analysis as supplementary
        print("Performing AI-assisted analysis...")
        ai_mapping = self._get_ai_mapping(log_sample)
        
        # Combine results (prioritize local analysis, supplement with AI)
        combined_mitre = {}
        combined_owasp = {}
        
        # Add local analysis results
        for technique in local_mapping.get("mitre_techniques", []):
            combined_mitre[technique["technique_id"]] = technique
        
        for vuln in local_mapping.get("owasp_vulnerabilities", []):
            combined_owasp[vuln["owasp_id"]] = vuln
        
        # Add AI results if they don't conflict
        for technique in ai_mapping.get("mitre_techniques", []):
            if technique["technique_id"] not in combined_mitre:
                combined_mitre[technique["technique_id"]] = technique
        
        for vuln in ai_mapping.get("owasp_vulnerabilities", []):
            if vuln["owasp_id"] not in combined_owasp:
                combined_owasp[vuln["owasp_id"]] = vuln
        
        # Convert to final format
        mitre_techniques = []
        for technique_id, technique in combined_mitre.items():
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
        for owasp_id, vuln in combined_owasp.items():
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
        
        print(f"Found {len(mitre_techniques)} MITRE techniques and {len(owasp_vulnerabilities)} OWASP vulnerabilities")
        
        return FrameworkMapping(
            mitre_techniques=mitre_techniques,
            owasp_vulnerabilities=owasp_vulnerabilities
        )
    
    def _get_ai_mapping(self, log_sample: str) -> Dict[str, Any]:
        """Get AI analysis of log patterns"""
        try:
            # Prepare a more focused prompt
            prompt = f"""Analyze these web server logs for cybersecurity attacks and map them to security frameworks.

LOG ENTRIES:
{log_sample}

ANALYSIS INSTRUCTIONS:
1. Identify specific attack patterns in the logs
2. Map each attack to appropriate MITRE ATT&CK techniques and OWASP Top 10 vulnerabilities
3. Look for: SQL injection, command injection, directory traversal, brute force, reconnaissance

AVAILABLE MITRE TECHNIQUES:
- T1110: Brute Force
- T1190: Exploit Public-Facing Application  
- T1059: Command and Scripting Interpreter
- T1083: File and Directory Discovery
- T1046: Network Service Scanning

AVAILABLE OWASP CATEGORIES:
- A01:2021: Broken Access Control
- A03:2021: Injection
- A05:2021: Security Misconfiguration
- A07:2021: Identification and Authentication Failures

OUTPUT ONLY VALID JSON:
{{
    "mitre_techniques": [
        {{
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "confidence": 0.9,
            "severity": "HIGH"
        }}
    ],
    "owasp_vulnerabilities": [
        {{
            "owasp_id": "A03:2021", 
            "name": "Injection",
            "confidence": 0.9,
            "severity": "HIGH"
        }}
    ]
}}"""
            
            response = self.ai.invoke(prompt)
            return self._parse_mapping_response(response.content)
            
        except Exception as e:
            print(f"AI analysis failed: {str(e)}")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
    
    def _parse_mapping_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response for framework mapping"""
        try:
            # Clean the response
            response_text = response_text.strip()
            
            # Remove any markdown formatting
            response_text = re.sub(r'```json\s*', '', response_text)
            response_text = re.sub(r'```\s*$', '', response_text)
            
            # Find JSON content
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start != -1 and json_end > json_start:
                json_content = response_text[json_start:json_end]
                parsed = json.loads(json_content)
                
                # Validate the structure
                if isinstance(parsed, dict) and "mitre_techniques" in parsed and "owasp_vulnerabilities" in parsed:
                    return parsed
            
            print("No valid JSON structure found in AI response")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse AI response as JSON: {e}")
            print(f"Response content: {response_text[:500]}...")  # Debug info
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
        except Exception as e:
            print(f"Error parsing AI response: {e}")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}