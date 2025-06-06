import os
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
import aiofiles

from models import ForensicReport, TimelineEvent, FrameworkMapping, ThreatDetection
from services.threat_mapping import ThreatMappingService
from services.dashboard_service import DashboardService
from services.ip_enrichment import IPEnrichmentService
from config import settings

class ReportGeneratorService:
    def __init__(self, 
                 threat_mapping_service: ThreatMappingService,
                 dashboard_service: DashboardService,
                 ip_enrichment_service: IPEnrichmentService):
        self.threat_mapping = threat_mapping_service
        self.dashboard = dashboard_service
        self.ip_enrichment = ip_enrichment_service
        
        # Ensure report directory exists
        os.makedirs(settings.REPORT_STORAGE_PATH, exist_ok=True)
    
    async def generate_forensic_report(self, 
                                 log_content: str, 
                                 threats: List[ThreatDetection], 
                                 ai_analysis: str) -> ForensicReport:
        """Generate a comprehensive forensic report"""
        # Generate a unique report ID
        report_id = str(uuid.uuid4())
        
        # Get framework mappings
        framework_mapping = self.threat_mapping.map_threats_to_frameworks(threats, log_content)
        
        # Get timeline events
        timeline_events = self.dashboard.extract_timeline_events(log_content, threats)
        
        # Get enriched IPs
        enriched_ips = self.ip_enrichment.create_enriched_ip_report(log_content)
        
        # Extract key findings from AI analysis
        key_findings = self._extract_key_findings(ai_analysis)
        
        # Extract executive summary from AI analysis
        executive_summary = self._extract_executive_summary(ai_analysis)
        
        # Create indicators of compromise
        iocs = []
        for threat in threats:
            ioc = {
                "type": threat.type,
                "indicator": threat.description,
                "severity": threat.severity
            }
            iocs.append(ioc)
        
        # Create threat actors section based on suspicious IPs
        threat_actors = []
        for ip in enriched_ips:
            if ip.geo_data.is_threat:
                actor = {
                    "identifier": ip.ip,
                    "location": f"{ip.geo_data.city}, {ip.geo_data.country}" if ip.geo_data.city else ip.geo_data.country,
                    "threat_score": ip.geo_data.threat_score,
                    "activity": ip.associated_events[:3] if ip.associated_events else ["Unknown activity"]
                }
                threat_actors.append(actor)
        
        # Create recommendations based on framework mappings
        recommendations = []
        for technique in framework_mapping.mitre_techniques:
            rec = {
                "title": f"Mitigate {technique.name}",
                "description": f"Implement controls to prevent {technique.technique_id}: {technique.name}",
                "priority": technique.severity,
                "reference": technique.url
            }
            recommendations.append(rec)
        
        for vuln in framework_mapping.owasp_vulnerabilities:
            rec = {
                "title": f"Fix {vuln.name}",
                "description": f"Address {vuln.owasp_id}: {vuln.name} vulnerability",
                "priority": vuln.severity,
                "reference": vuln.url
            }
            recommendations.append(rec)
        
        # Create affected systems list based on targeted endpoints
        affected_systems = set()
        for event in timeline_events:
            if event.target and event.severity in ["HIGH", "CRITICAL"]:
                # Extract domain/path from target
                parts = event.target.split('/')
                if len(parts) > 1:
                    affected_systems.add(parts[1])
        
        # Create technical details
        technical_details = {
            "log_size": len(log_content),
            "line_count": len(log_content.splitlines()),
            "unique_ips": len(enriched_ips),
            "threat_count": len(threats),
            "timeline_event_count": len(timeline_events),
            "geographic_distribution": self._count_countries(enriched_ips),
            "attack_types": {t.type: t.count for t in threats}
        }
        
        # Create the report
        report = ForensicReport(
            report_id=report_id,
            generated_at=datetime.now(),
            executive_summary=executive_summary,
            key_findings=key_findings,
            threat_actors=threat_actors,
            indicators_of_compromise=iocs,
            attack_timeline=timeline_events,
            framework_mapping=framework_mapping,
            affected_systems=list(affected_systems),
            recommendations=recommendations,
            technical_details=technical_details
        )
        
        # Save the report to disk
        await self._save_report(report)
        
        return report
    
    def _extract_key_findings(self, ai_analysis: str) -> List[str]:
        """Extract key findings from AI analysis"""
        findings = []
        
        # Look for bullet points in the analysis
        lines = ai_analysis.splitlines()
        for line in lines:
            if line.strip().startswith("- ") or line.strip().startswith("* "):
                findings.append(line.strip()[2:])  # Remove the bullet point
        
        # If no bullet points found, try to extract sentences
        if not findings:
            import re
            sentences = re.split(r'(?<=[.!?])\s+', ai_analysis)
            for sentence in sentences[:5]:  # Take up to 5 sentences
                if len(sentence) > 20:  # Only include substantial sentences
                    findings.append(sentence)
        
        return findings[:10]  # Limit to 10 findings
    
    def _extract_executive_summary(self, ai_analysis: str) -> str:
        """Extract executive summary from AI analysis"""
        # Look for "Executive Summary" section
        if "Executive Summary:" in ai_analysis:
            parts = ai_analysis.split("Executive Summary:")
            if len(parts) > 1:
                summary_part = parts[1].split("\n\n")[0].strip()
                return summary_part
        
        # If no explicit section, take the first paragraph
        paragraphs = ai_analysis.split("\n\n")
        if paragraphs:
            return paragraphs[0].strip()
        
        return "No executive summary available."
    
    def _count_countries(self, enriched_ips) -> Dict[str, int]:
        """Count IPs by country"""
        countries = {}
        for ip in enriched_ips:
            country = ip.geo_data.country
            if country in countries:
                countries[country] += 1
            else:
                countries[country] = 1
        return countries
    
    async def _save_report(self, report: ForensicReport) -> None:
        """Save report to disk"""
        report_path = os.path.join(settings.REPORT_STORAGE_PATH, f"{report.report_id}.json")
        
        # Convert to dict for JSON serialization
        report_dict = report.dict()
        
        # Convert datetime objects to strings
        report_dict["generated_at"] = report_dict["generated_at"].isoformat()
        for event in report_dict["attack_timeline"]:
            event["timestamp"] = event["timestamp"].isoformat()
        
        # Save to file
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report_dict, indent=2))
    
    async def get_report(self, report_id: str) -> Optional[ForensicReport]:
        """Retrieve a saved report by ID"""
        report_path = os.path.join(settings.REPORT_STORAGE_PATH, f"{report_id}.json")
        
        if not os.path.exists(report_path):
            return None
        
        try:
            async with aiofiles.open(report_path, 'r') as f:
                content = await f.read()
                report_dict = json.loads(content)
                
                # Convert string timestamps back to datetime objects
                report_dict["generated_at"] = datetime.fromisoformat(report_dict["generated_at"])
                for event in report_dict["attack_timeline"]:
                    event["timestamp"] = datetime.fromisoformat(event["timestamp"])
                
                return ForensicReport(**report_dict)
        except Exception as e:
            print(f"Error loading report {report_id}: {str(e)}")
            return None
    
    async def list_reports(self) -> List[Dict[str, Any]]:
        """List all available reports with basic metadata"""
        reports = []
        
        try:
            for filename in os.listdir(settings.REPORT_STORAGE_PATH):
                if filename.endswith(".json"):
                    report_path = os.path.join(settings.REPORT_STORAGE_PATH, filename)
                    async with aiofiles.open(report_path, 'r') as f:
                        content = await f.read()
                        report_dict = json.loads(content)
                        
                        # Include only basic metadata
                        reports.append({
                            "report_id": report_dict["report_id"],
                            "generated_at": report_dict["generated_at"],
                            "executive_summary": report_dict["executive_summary"][:100] + "..." if len(report_dict["executive_summary"]) > 100 else report_dict["executive_summary"],
                            "threat_count": len(report_dict["indicators_of_compromise"]),
                            "affected_systems_count": len(report_dict["affected_systems"])
                        })
        except Exception as e:
            print(f"Error listing reports: {str(e)}")
        
        # Sort by generation time (newest first)
        return sorted(reports, key=lambda r: r["generated_at"], reverse=True)