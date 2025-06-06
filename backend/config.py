import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY")
    MODEL_NAME: str = "llama3-70b-8192"
    TEMPERATURE: float = 0.1
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: set = {'.txt', '.log'}
    
    # GeoIP settings
    GEOIP_PROVIDER: str = os.getenv("GEOIP_PROVIDER", "ip-api")  # Options: ip-api, ipinfo, ipgeolocation, ip2location
    IP2LOCATION_DB_PATH: str = os.getenv("IP2LOCATION_DB_PATH", "./data/IP2LOCATION-LITE-DB5.BIN")
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")  # Optional for ipinfo.io
    MAXMIND_DB_PATH: str = os.getenv("MAXMIND_DB_PATH", "./data/GeoLite2-City.mmdb")
    MAXMIND_LICENSE_KEY: str = os.getenv("MAXMIND_LICENSE_KEY", "")
    
    # Threat Intelligence settings
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # Report settings
    REPORT_STORAGE_PATH: str = os.getenv("REPORT_STORAGE_PATH", "./reports")

settings = Settings()