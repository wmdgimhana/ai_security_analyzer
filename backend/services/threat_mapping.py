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
            },
            "T1562": {
                "name": "Impair Defenses",
                "description": "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms.",
                "url": "https://attack.mitre.org/techniques/T1562/"
            },
            "T1018": {
                "name": "Remote System Discovery",
                "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.",
                "url": "https://attack.mitre.org/techniques/T1018/"
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
            "A02:2021": {
                "name": "Cryptographic Failures",
                "description": "Failures related to cryptography which often leads to sensitive data exposure.",
                "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            },
            "A03:2021": {
                "name": "Injection",
                "description": "Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.",
                "url": "https://owasp.org/Top10/A03_2021-Injection/"
            },
            "A04:2021": {
                "name": "Insecure Design",
                "description": "Insecure design is a broad category representing different weaknesses, expressed as 'missing or ineffective control design'.",
                "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"
            },
            "A05:2021": {
                "name": "Security Misconfiguration",
                "description": "Security misconfiguration is the most commonly seen issue, often resulting from insecure default configurations or incomplete configurations.",
                "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            },
            "A06:2021": {
                "name": "Vulnerable and Outdated Components",
                "description": "Components run with the same privileges as the application itself, so flaws in any component can result in serious impact.",
                "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
            },
            "A07:2021": {
                "name": "Identification and Authentication Failures",
                "description": "Authentication failures can allow attackers to assume other users' identities.",
                "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
            },
            "A08:2021": {
                "name": "Software and Data Integrity Failures",
                "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
                "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
            },
            "A09:2021": {
                "name": "Security Logging and Monitoring Failures",
                "description": "Logging and monitoring failures can allow attackers to further attack systems, maintaining persistence, and tampering or destroying data.",
                "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
            },
            "A10:2021": {
                "name": "Server-Side Request Forgery",
                "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
                "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
            }
        }
    
    def _validate_with_hardcoded_patterns(self, log_sample: str, ai_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use hardcoded patterns to validate and enhance AI results"""
        validation_results = {
            "validated_attacks": [],
            "additional_findings": [],
            "confidence_adjustments": {}
        }
        
        # Define pattern categories with associated frameworks
        pattern_mappings = {
            "SQL_INJECTION": {
                "patterns": [
                    r"(?i)(union\s+select|or\s+1\s*=\s*1|'.*'=.*'|admin'--|%27|sqlmap)",
                    r"(?i)(\bor\b.*\b1\b.*\b=\b.*\b1\b|'\s*or\s*'1'\s*=\s*'1)",
                    r"(?i)(select.*from.*information_schema|benchmark\(|sleep\(|waitfor\s+delay)",
                    r"(?i)(char\(\d+\)|concat\(|hex\(|unhex\(|load_file\()"
                ],
                "mitre": {"technique_id": "T1190", "name": "Exploit Public-Facing Application"},
                "owasp": {"owasp_id": "A03:2021", "name": "Injection"}
            },
            "COMMAND_INJECTION": {
                "patterns": [
                    r"(?i)(cmd=|;.*whoami|;.*ls|;.*cat|%7C|pipe|&.*whoami)",
                    r"(?i)(\|whoami|\|ls|\|cat|%7Cwhoami)",
                    r"(?i)(bash|sh|cmd\.exe|powershell|eval\(|exec\(|system\()",
                    r"(?i)(`.*`|\$\(.*\)|<%.*%>)"
                ],
                "mitre": {"technique_id": "T1059", "name": "Command and Scripting Interpreter"},
                "owasp": {"owasp_id": "A03:2021", "name": "Injection"}
            },
            "DIRECTORY_TRAVERSAL": {
                "patterns": [
                    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\/etc\/passwd|\/etc\/shadow)",
                    r"(?i)(\.\..*\/.*\/.*etc|file=.*\.\./|\.\..*\/.*\/.*windows)",
                    r"(?i)(%252e%252e|..%252f|..%255c)"
                ],
                "mitre": {"technique_id": "T1083", "name": "File and Directory Discovery"},
                "owasp": {"owasp_id": "A01:2021", "name": "Broken Access Control"}
            },
            "BRUTE_FORCE": {
                "patterns": [
                    r"(?i)(wp-login\.php|admin.*login|login.*admin)",
                    r"(?i)(nikto|dirb|gobuster|hydra|nmap|masscan)",
                    r"(?i)(401.*401.*401|403.*403.*403)",  # Multiple failed attempts
                    r"(?i)(password.*password.*password|login.*failed.*failed)"
                ],
                "mitre": {"technique_id": "T1110", "name": "Brute Force"},
                "owasp": {"owasp_id": "A07:2021", "name": "Identification and Authentication Failures"}
            },
            "XSS": {
                "patterns": [
                    r"(?i)(<script|javascript:|vbscript:|onload=|onerror=)",
                    r"(?i)(%3cscript|%3e%3cscript|alert\(|prompt\(|confirm\()",
                    r"(?i)(document\.cookie|window\.location|eval\(.*\))"
                ],
                "mitre": {"technique_id": "T1190", "name": "Exploit Public-Facing Application"},
                "owasp": {"owasp_id": "A03:2021", "name": "Injection"}
            },
            "RECONNAISSANCE": {
                "patterns": [
                    r"(?i)(\/\.well-known|robots\.txt|sitemap\.xml)",
                    r"(?i)(nmap|masscan|zmap|dirb|dirbuster)",
                    r"(?i)(admin|phpmyadmin|wp-admin|\.git|\.env|config\.php)"
                ],
                "mitre": {"technique_id": "T1046", "name": "Network Service Scanning"},
                "owasp": {"owasp_id": "A05:2021", "name": "Security Misconfiguration"}
            }
        }
        
        log_lines = log_sample.split('\n')
        detected_patterns = set()
        
        for line in log_lines:
            if not line.strip():
                continue
                
            for attack_type, config in pattern_mappings.items():
                for pattern in config["patterns"]:
                    if re.search(pattern, line):
                        detected_patterns.add(attack_type)
                        break
        
        # Validate AI findings against hardcoded patterns
        ai_mitre_ids = {t["technique_id"] for t in ai_results.get("mitre_techniques", [])}
        ai_owasp_ids = {v["owasp_id"] for v in ai_results.get("owasp_vulnerabilities", [])}
        
        for attack_type in detected_patterns:
            config = pattern_mappings[attack_type]
            mitre_id = config["mitre"]["technique_id"]
            owasp_id = config["owasp"]["owasp_id"]
            
            # If AI also detected this, increase confidence
            if mitre_id in ai_mitre_ids:
                validation_results["confidence_adjustments"][mitre_id] = 0.9  # High confidence
                validation_results["validated_attacks"].append(attack_type)
            else:
                # AI missed this, add as additional finding with medium confidence
                validation_results["additional_findings"].append({
                    "attack_type": attack_type,
                    "mitre": config["mitre"],
                    "owasp": config["owasp"],
                    "confidence": 0.7,
                    "source": "hardcoded_pattern"
                })
        
        return validation_results
    
    def map_threats_to_frameworks(self, threats: List[ThreatDetection], log_sample: str) -> FrameworkMapping:
        """Map detected threats to MITRE ATT&CK and OWASP Top 10 frameworks (AI-Primary approach)"""
        if not log_sample.strip():
            return FrameworkMapping(
                mitre_techniques=[],
                owasp_vulnerabilities=[]
            )
        
        # PRIMARY: AI Analysis
        print("Performing AI-assisted threat analysis (Primary)...")
        ai_mapping = self._get_ai_mapping(log_sample)
        
        # SECONDARY: Hardcoded pattern validation and enhancement
        print("Validating with hardcoded patterns (Secondary)...")
        validation_results = self._validate_with_hardcoded_patterns(log_sample, ai_mapping)
        
        # Combine results with AI as primary
        final_mapping = self._combine_ai_and_validation(ai_mapping, validation_results)
        
        # Convert to final format
        mitre_techniques = []
        for technique_data in final_mapping.get("mitre_techniques", []):
            technique_id = technique_data["technique_id"]
            if technique_id in self.mitre_data:
                reference = self.mitre_data[technique_id]
                mitre_techniques.append(MITREAttackTechnique(
                    technique_id=technique_id,
                    name=technique_data.get("name", reference["name"]),
                    description=reference["description"],
                    url=reference["url"],
                    severity=technique_data.get("severity", "MEDIUM"),
                    confidence=technique_data.get("confidence", 0.5)
                ))
        
        owasp_vulnerabilities = []
        for vuln_data in final_mapping.get("owasp_vulnerabilities", []):
            owasp_id = vuln_data["owasp_id"]
            if owasp_id in self.owasp_data:
                reference = self.owasp_data[owasp_id]
                owasp_vulnerabilities.append(OWASPVulnerability(
                    owasp_id=owasp_id,
                    name=vuln_data.get("name", reference["name"]),
                    description=reference["description"],
                    url=reference["url"],
                    severity=vuln_data.get("severity", "MEDIUM"),
                    confidence=vuln_data.get("confidence", 0.5)
                ))
        
        print(f"Final results: {len(mitre_techniques)} MITRE techniques and {len(owasp_vulnerabilities)} OWASP vulnerabilities")
        
        return FrameworkMapping(
            mitre_techniques=mitre_techniques,
            owasp_vulnerabilities=owasp_vulnerabilities
        )
    
    def _combine_ai_and_validation(self, ai_mapping: Dict[str, Any], validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine AI results with validation results, prioritizing AI"""
        combined_mitre = {}
        combined_owasp = {}
        
        # Start with AI results as primary
        for technique in ai_mapping.get("mitre_techniques", []):
            technique_id = technique["technique_id"]
            # Apply confidence adjustments from validation
            if technique_id in validation_results["confidence_adjustments"]:
                technique["confidence"] = validation_results["confidence_adjustments"][technique_id]
                technique["validated"] = True
            combined_mitre[technique_id] = technique
        
        for vuln in ai_mapping.get("owasp_vulnerabilities", []):
            owasp_id = vuln["owasp_id"]
            combined_owasp[owasp_id] = vuln
        
        # Add additional findings from hardcoded patterns that AI missed
        for finding in validation_results["additional_findings"]:
            mitre_data = finding["mitre"]
            owasp_data = finding["owasp"]
            
            if mitre_data["technique_id"] not in combined_mitre:
                combined_mitre[mitre_data["technique_id"]] = {
                    "technique_id": mitre_data["technique_id"],
                    "name": mitre_data["name"],
                    "confidence": finding["confidence"],
                    "severity": "MEDIUM",
                    "source": finding["source"]
                }
            
            if owasp_data["owasp_id"] not in combined_owasp:
                combined_owasp[owasp_data["owasp_id"]] = {
                    "owasp_id": owasp_data["owasp_id"],
                    "name": owasp_data["name"],
                    "confidence": finding["confidence"],
                    "severity": "MEDIUM",
                    "source": finding["source"]
                }
        
        return {
            "mitre_techniques": list(combined_mitre.values()),
            "owasp_vulnerabilities": list(combined_owasp.values())
        }
    
    def _get_ai_mapping(self, log_sample: str) -> Dict[str, Any]:
        """Get comprehensive AI analysis of log patterns"""
        try:
            # Enhanced prompt for better AI analysis
            available_mitre = "\n".join([f"- {k}: {v['name']}" for k, v in self.mitre_data.items()])
            available_owasp = "\n".join([f"- {k}: {v['name']}" for k, v in self.owasp_data.items()])
            
            prompt = f"""Analyze web server logs for cybersecurity threats and return ONLY valid JSON.

LOG ENTRIES:
{log_sample}

DETECT THESE ATTACK TYPES:
- SQL injection, Command injection, XSS
- Directory traversal, Path manipulation  
- Brute force, Authentication attacks
- Reconnaissance, Scanning activities
- SSRF, File upload attacks

MAP TO FRAMEWORKS:
MITRE ATT&CK: {available_mitre}
OWASP TOP 10: {available_owasp}

CRITICAL: Return ONLY valid JSON with NO additional text, explanations, or markdown formatting.

FORMAT (exact structure required):
{{
    "mitre_techniques": [
        {{
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application", 
            "confidence": 0.9,
            "severity": "HIGH",
            "evidence": "SQL injection detected"
        }}
    ],
    "owasp_vulnerabilities": [
        {{
            "owasp_id": "A03:2021",
            "name": "Injection",
            "confidence": 0.9, 
            "severity": "HIGH",
            "evidence": "Injection patterns found"
        }}
    ]
}}

RULES:
- confidence: 0.1 to 1.0 (float)
- severity: LOW, MEDIUM, HIGH, or CRITICAL
- Use only technique_id and owasp_id from the lists above
- NO trailing commas in JSON
- NO control characters or special formatting
- NO explanatory text before or after JSON"""
            
            response = self.ai.invoke(prompt)
            return self._parse_mapping_response(response.content)
            
        except Exception as e:
            print(f"AI analysis failed: {str(e)}")
            # Return empty results if AI fails
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
    
    def _parse_mapping_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI response for framework mapping with enhanced error handling and JSON repair"""
        try:
            # Clean the response
            response_text = response_text.strip()
            
            # Remove any markdown formatting
            response_text = re.sub(r'```json\s*', '', response_text)
            response_text = re.sub(r'```\s*', '', response_text)
            response_text = re.sub(r'^```\s*', '', response_text)
            response_text = re.sub(r'^Here.*?analysis.*?logs?:?\s*', '', response_text, flags=re.IGNORECASE | re.DOTALL)
            
            # Clean up control characters and invalid JSON characters
            response_text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', response_text)  # Remove control characters
            response_text = re.sub(r'\n\s*\n', '\n', response_text)  # Remove extra newlines
            
            # Find JSON content - try multiple approaches
            json_content = None
            
            # Approach 1: Look for complete JSON object
            json_start = response_text.find('{')
            if json_start != -1:
                # Find matching closing brace
                brace_count = 0
                for i, char in enumerate(response_text[json_start:], json_start):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_content = response_text[json_start:i+1]
                            break
            
            # Approach 2: If no complete object found, try to repair common issues
            if not json_content:
                # Look for partial JSON and try to repair
                partial_json = response_text[json_start:] if json_start != -1 else response_text
                
                # Fix common JSON issues
                partial_json = re.sub(r',(\s*[}\]])', r'\1', partial_json)  # Remove trailing commas
                partial_json = re.sub(r'([^"])"([^":])', r'\1"\2', partial_json)  # Fix unescaped quotes
                partial_json = re.sub(r'"([^"]*)"([^",:\[\]{}]*)"', r'"\1\2"', partial_json)  # Fix broken strings
                
                # Try to find a valid JSON structure again
                json_start = partial_json.find('{')
                if json_start != -1:
                    brace_count = 0
                    for i, char in enumerate(partial_json[json_start:], json_start):
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                json_content = partial_json[json_start:i+1]
                                break
            
            # Approach 3: If still no luck, try to extract key information manually
            if not json_content:
                print("Attempting to extract information from malformed response...")
                return self._extract_from_malformed_response(response_text)
            
            # Try to parse the JSON
            try:
                parsed = json.loads(json_content)
            except json.JSONDecodeError as e:
                print(f"First JSON parse attempt failed: {e}")
                # Try to fix common JSON issues and parse again
                json_content = self._repair_json(json_content)
                try:
                    parsed = json.loads(json_content)
                except json.JSONDecodeError as e2:
                    print(f"Second JSON parse attempt failed: {e2}")
                    print(f"Problematic JSON: {json_content[:500]}...")
                    return self._extract_from_malformed_response(response_text)
            
            # Validate and clean the structure
            if isinstance(parsed, dict):
                # Ensure required keys exist
                if "mitre_techniques" not in parsed:
                    parsed["mitre_techniques"] = []
                if "owasp_vulnerabilities" not in parsed:
                    parsed["owasp_vulnerabilities"] = []
                
                # Validate MITRE techniques
                valid_mitre = []
                for technique in parsed.get("mitre_techniques", []):
                    if isinstance(technique, dict) and "technique_id" in technique:
                        # Ensure confidence is a float between 0 and 1
                        if "confidence" in technique:
                            try:
                                technique["confidence"] = max(0.0, min(1.0, float(technique["confidence"])))
                            except (ValueError, TypeError):
                                technique["confidence"] = 0.5
                        else:
                            technique["confidence"] = 0.5
                        
                        # Ensure severity is valid
                        if "severity" not in technique or technique["severity"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                            technique["severity"] = "MEDIUM"
                        
                        valid_mitre.append(technique)
                
                # Validate OWASP vulnerabilities
                valid_owasp = []
                for vuln in parsed.get("owasp_vulnerabilities", []):
                    if isinstance(vuln, dict) and "owasp_id" in vuln:
                        # Ensure confidence is a float between 0 and 1
                        if "confidence" in vuln:
                            try:
                                vuln["confidence"] = max(0.0, min(1.0, float(vuln["confidence"])))
                            except (ValueError, TypeError):
                                vuln["confidence"] = 0.5
                        else:
                            vuln["confidence"] = 0.5
                        
                        # Ensure severity is valid
                        if "severity" not in vuln or vuln["severity"] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                            vuln["severity"] = "MEDIUM"
                        
                        valid_owasp.append(vuln)
                
                return {
                    "mitre_techniques": valid_mitre,
                    "owasp_vulnerabilities": valid_owasp
                }
            
            print("No valid JSON structure found in AI response")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
            
        except Exception as e:
            print(f"Error parsing AI response: {e}")
            print(f"Response content: {response_text[:500]}...")
            return {"mitre_techniques": [], "owasp_vulnerabilities": []}
    
    def _repair_json(self, json_str: str) -> str:
        """Attempt to repair common JSON formatting issues"""
        # Remove trailing commas before closing brackets/braces
        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
        
        # Fix unescaped quotes in strings
        json_str = re.sub(r'(?<!\\)"(?=[^",:\[\]{}]*[",:\[\]{}])', r'\\"', json_str)
        
        # Fix missing quotes around keys
        json_str = re.sub(r'(\w+)(\s*:)', r'"\1"\2', json_str)
        
        # Fix incomplete strings at the end
        if json_str.count('"') % 2 != 0:
            json_str += '"'
        
        # Ensure proper closing
        open_braces = json_str.count('{') - json_str.count('}')
        open_brackets = json_str.count('[') - json_str.count(']')
        
        json_str += '}' * open_braces
        json_str += ']' * open_brackets
        
        return json_str
    
    def _extract_from_malformed_response(self, response_text: str) -> Dict[str, Any]:
        """Extract threat information from malformed AI response using pattern matching"""
        print("Extracting information from malformed response using fallback method...")
        
        mitre_techniques = []
        owasp_vulnerabilities = []
        
        # Look for technique IDs mentioned in the response
        technique_pattern = r'T\d{4}'
        owasp_pattern = r'A\d{2}:2021'
        
        found_techniques = re.findall(technique_pattern, response_text)
        found_owasp = re.findall(owasp_pattern, response_text)
        
        # Map found techniques to our data
        for tech_id in set(found_techniques):
            if tech_id in self.mitre_data:
                mitre_techniques.append({
                    "technique_id": tech_id,
                    "name": self.mitre_data[tech_id]["name"],
                    "confidence": 0.6,  # Lower confidence for extracted data
                    "severity": "MEDIUM"
                })
        
        for owasp_id in set(found_owasp):
            if owasp_id in self.owasp_data:
                owasp_vulnerabilities.append({
                    "owasp_id": owasp_id,
                    "name": self.owasp_data[owasp_id]["name"],
                    "confidence": 0.6,  # Lower confidence for extracted data
                    "severity": "MEDIUM"
                })
        
        # If still no results, infer from keywords
        if not mitre_techniques and not owasp_vulnerabilities:
            keywords_to_mitre = {
                'sql injection': ("T1190", "HIGH"),
                'command injection': ("T1059", "HIGH"),
                'directory traversal': ("T1083", "MEDIUM"),
                'brute force': ("T1110", "MEDIUM"),
                'scanning': ("T1046", "LOW")
            }
            
            keywords_to_owasp = {
                'injection': ("A03:2021", "HIGH"),
                'access control': ("A01:2021", "HIGH"),
                'authentication': ("A07:2021", "MEDIUM"),
                'misconfiguration': ("A05:2021", "MEDIUM")
            }
            
            response_lower = response_text.lower()
            
            for keyword, (tech_id, severity) in keywords_to_mitre.items():
                if keyword in response_lower and tech_id in self.mitre_data:
                    mitre_techniques.append({
                        "technique_id": tech_id,
                        "name": self.mitre_data[tech_id]["name"],
                        "confidence": 0.4,  # Even lower confidence for keyword matching
                        "severity": severity
                    })
            
            for keyword, (owasp_id, severity) in keywords_to_owasp.items():
                if keyword in response_lower and owasp_id in self.owasp_data:
                    owasp_vulnerabilities.append({
                        "owasp_id": owasp_id,
                        "name": self.owasp_data[owasp_id]["name"],
                        "confidence": 0.4,  # Even lower confidence for keyword matching
                        "severity": severity
                    })
        
        return {
            "mitre_techniques": mitre_techniques,
            "owasp_vulnerabilities": owasp_vulnerabilities
        }