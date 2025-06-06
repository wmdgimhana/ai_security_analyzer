import os
import json
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import geoip2.database
from geoip2.errors import AddressNotFoundError

from models import GeoIPInfo, EnrichedIP
from config import settings
# Add this import
import IP2Location

class IPEnrichmentService:
    def __init__(self):
        # Initialize GeoIP database
        self.geoip_reader = None
        self.setup_geoip_db()
        
        # Cache for IP lookups to reduce API calls
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
    
    def setup_geoip_db(self):
        """Set up the IP2Location database reader"""
        try:
            db_path = os.getenv("IP2LOCATION_DB_PATH", "./data/IP2LOCATION-LITE-DB5.BIN")
            if os.path.exists(db_path):
                self.ip2location = IP2Location.IP2Location(db_path)
                print("✅ IP2Location database loaded successfully")
            else:
                print(f"⚠️ IP2Location database not found at {db_path}")
        except Exception as e:
            print(f"❌ Error loading IP2Location database: {str(e)}")
    
    def enrich_ip(self, ip: str) -> GeoIPInfo:
        """Enrich an IP with geolocation and threat intelligence"""
        # Check cache first
        if ip in self.ip_cache:
            return GeoIPInfo(**self.ip_cache[ip])
        
        # Default values
        geo_data = {
            "ip": ip,
            "country": "Unknown",
            "city": None,
            "latitude": None,
            "longitude": None,
            "isp": None,
            "is_threat": False,
            "threat_type": None,
            "threat_score": None,
            "last_reported": None
        }
        
        # Get GeoIP data from ipgeolocation.io
        try:
            # You can use without API key for limited requests
            response = requests.get(f"https://api.ipgeolocation.io/ipgeo?ip={ip}")
            if response.status_code == 200:
                data = response.json()
                geo_data["country"] = data.get("country_name", "Unknown")
                geo_data["city"] = data.get("city")
                geo_data["latitude"] = data.get("latitude")
                geo_data["longitude"] = data.get("longitude")
                geo_data["isp"] = data.get("isp")
        except Exception as e:
            print(f"Error in GeoIP lookup for {ip}: {str(e)}")
        
        # Get GeoIP data from IP2Location
        try:
            if hasattr(self, 'ip2location'):
                rec = self.ip2location.get_all(ip)
                geo_data["country"] = rec.country_long or "Unknown"
                geo_data["city"] = rec.city
                geo_data["latitude"] = rec.latitude
                geo_data["longitude"] = rec.longitude
        except Exception as e:
            print(f"Error in GeoIP lookup for {ip}: {str(e)}")
        
        # Get threat intelligence data if API key is available
        if settings.ABUSEIPDB_API_KEY:
            try:
                headers = {
                    'Key': settings.ABUSEIPDB_API_KEY,
                    'Accept': 'application/json',
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                }
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    abuse_score = data.get('abuseConfidenceScore', 0)
                    
                    if abuse_score > 0:
                        geo_data["is_threat"] = True
                        geo_data["threat_score"] = abuse_score
                        geo_data["threat_type"] = "Abuse Reports"
                        geo_data["isp"] = data.get('isp')
                        
                        # Convert last reported time if available
                        if data.get('lastReportedAt'):
                            geo_data["last_reported"] = datetime.fromisoformat(data.get('lastReportedAt').replace('Z', '+00:00'))
            except Exception as e:
                print(f"Error in threat intelligence lookup for {ip}: {str(e)}")
        
        # Cache the result
        self.ip_cache[ip] = geo_data
        
        return GeoIPInfo(**geo_data)
    
    def enrich_multiple_ips(self, ips: List[str]) -> List[GeoIPInfo]:
        """Enrich multiple IPs with geolocation and threat intelligence"""
        return [self.enrich_ip(ip) for ip in ips]
    
    def extract_ips_from_logs(self, log_content: str) -> List[str]:
        """Extract IP addresses from log content using regex"""
        import re
        # IPv4 regex pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        # Find all matches
        ips = re.findall(ip_pattern, log_content)
        
        # Remove duplicates while preserving order
        unique_ips = []
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.append(ip)
        
        return unique_ips
    
    def create_enriched_ip_report(self, log_content: str) -> List[EnrichedIP]:
        """Create a comprehensive report of all IPs in the logs with enrichment"""
        # Extract IPs
        ips = self.extract_ips_from_logs(log_content)
        
        # Count occurrences
        import re
        ip_counts = {}
        for ip in ips:
            pattern = re.escape(ip)
            ip_counts[ip] = len(re.findall(pattern, log_content))
        
        # Extract associated events (simplified)
        ip_events = {}
        for ip in ips:
            # Get lines containing this IP
            lines = [line for line in log_content.splitlines() if ip in line]
            # Take up to 5 events
            events = lines[:5]
            ip_events[ip] = events
        
        # Create enriched IP objects
        enriched_ips = []
        for ip in ips:
            geo_data = self.enrich_ip(ip)
            enriched_ip = EnrichedIP(
                ip=ip,
                geo_data=geo_data,
                occurrences=ip_counts.get(ip, 0),
                associated_events=ip_events.get(ip, [])
            )
            enriched_ips.append(enriched_ip)
        
        return enriched_ips