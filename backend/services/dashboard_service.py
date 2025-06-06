from typing import List, Dict, Any, Optional
from datetime import datetime
import re
import json

from models import TimelineEvent, DashboardData, ThreatDetection, GeoIPInfo
from services.ip_enrichment import IPEnrichmentService

class DashboardService:
    def __init__(self, ip_enrichment_service: IPEnrichmentService):
        self.ip_enrichment = ip_enrichment_service
    
    def extract_timestamps(self, log_content: str) -> List[datetime]:
        """Extract timestamps from log content"""
        # Common timestamp patterns
        patterns = [
            # ISO format: 2023-04-15T14:32:18
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
            # Common log format: 15/Apr/2023:14:32:18
            r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            # Simple date-time: 2023-04-15 14:32:18
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        ]
        
        timestamps = []
        for pattern in patterns:
            matches = re.findall(pattern, log_content)
            for match in matches:
                try:
                    if 'T' in match:  # ISO format
                        dt = datetime.fromisoformat(match)
                    elif '/' in match:  # Common log format
                        dt = datetime.strptime(match, "%d/%b/%Y:%H:%M:%S")
                    else:  # Simple date-time
                        dt = datetime.strptime(match, "%Y-%m-%d %H:%M:%S")
                    timestamps.append(dt)
                except ValueError:
                    continue
        
        return sorted(timestamps)
    
    def extract_timeline_events(self, log_content: str, threats: List[ThreatDetection]) -> List[TimelineEvent]:
        """Extract timeline events from log content and detected threats"""
        # Get all timestamps
        timestamps = self.extract_timestamps(log_content)
        if not timestamps:
            return []
        
        # Extract lines with timestamps and create events
        events = []
        lines = log_content.splitlines()
        
        # Map threats to severity levels
        threat_types = {threat.type: threat.severity for threat in threats}
        
        for line in lines:
            # Try to find a timestamp in this line
            line_timestamp = None
            for pattern in [
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
                r'(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})',
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
            ]:
                match = re.search(pattern, line)
                if match:
                    try:
                        timestamp_str = match.group(1)
                        if 'T' in timestamp_str:  # ISO format
                            line_timestamp = datetime.fromisoformat(timestamp_str)
                        elif '/' in timestamp_str:  # Common log format
                            line_timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
                        else:  # Simple date-time
                            line_timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        break
                    except ValueError:
                        continue
            
            if not line_timestamp:
                continue
            
            # Extract IP address if present
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            source_ip = ip_match.group(0) if ip_match else None
            
            # Determine event type and severity based on content
            event_type = "INFO"
            severity = "LOW"
            
            # Check if line contains any known threat types
            for threat_type, threat_severity in threat_types.items():
                if threat_type in line:
                    event_type = threat_type
                    severity = threat_severity
                    break
            
            # Check for common error/warning keywords
            if event_type == "INFO":
                if re.search(r'\b(error|fail|exception|denied)\b', line.lower()):
                    event_type = "ERROR"
                    severity = "MEDIUM"
                elif re.search(r'\b(warn|warning)\b', line.lower()):
                    event_type = "WARNING"
                    severity = "LOW"
            
            # Extract target (URL, endpoint, etc.) if present
            target_match = re.search(r'"(GET|POST|PUT|DELETE) ([^"]+)', line)
            target = target_match.group(2) if target_match else None
            
            # Create timeline event
            event = TimelineEvent(
                timestamp=line_timestamp,
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                target=target,
                description=line[:200]  # Truncate long lines
            )
            events.append(event)
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_dashboard_data(self, log_content: str, threats: List[ThreatDetection]) -> DashboardData:
        """Generate comprehensive dashboard data from log content and threats"""
        # Extract timeline events
        timeline_events = self.extract_timeline_events(log_content, threats)
        
        # Extract and enrich IPs
        ips = self.ip_enrichment.extract_ips_from_logs(log_content)
        geo_data = self.ip_enrichment.enrich_multiple_ips(ips)
        
        # Count IP frequencies
        ip_frequency = {}
        for ip in ips:
            pattern = re.escape(ip)
            ip_frequency[ip] = len(re.findall(pattern, log_content))
        
        # Count attack distribution
        attack_distribution = {}
        for threat in threats:
            if threat.type in attack_distribution:
                attack_distribution[threat.type] += threat.count
            else:
                attack_distribution[threat.type] = threat.count
        
        # Count severity distribution
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for threat in threats:
            if threat.severity in severity_counts:
                severity_counts[threat.severity] += 1
        
        return DashboardData(
            timeline_events=timeline_events,
            ip_frequency=ip_frequency,
            attack_distribution=attack_distribution,
            severity_counts=severity_counts,
            geographic_data=geo_data
        )