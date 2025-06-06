from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List, Optional

from models import (
    LogAnalysisRequest, AnalysisResponse, UploadResponse, ErrorResponse, 
    PatternAnalysisResponse, GeoIPInfo, EnrichedIP, FrameworkMapping, 
    DashboardData, ForensicReport
)
from services.log_analyzer import LogAnalyzerService
from services.ip_enrichment import IPEnrichmentService
from services.threat_mapping import ThreatMappingService
from services.dashboard_service import DashboardService
from services.report_generator import ReportGeneratorService
from utils.file_handler import FileHandler

app = FastAPI(
    title="AI Log Security Analyzer",
    description="Analyze server logs for security threats using AI - No hardcoded patterns, pure AI intelligence",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
try:
    log_analyzer = LogAnalyzerService()
    ip_enrichment = IPEnrichmentService()
    threat_mapping = ThreatMappingService()
    dashboard_service = DashboardService(ip_enrichment)
    report_generator = ReportGeneratorService(threat_mapping, dashboard_service, ip_enrichment)
    print("✅ AI Log Analyzer initialized successfully")
    print("✅ IP Enrichment service initialized successfully")
    print("✅ Threat Mapping service initialized successfully")
    print("✅ Dashboard service initialized successfully")
    print("✅ Report Generator service initialized successfully")
except ValueError as e:
    print(f"❌ Error initializing services: {e}")
    log_analyzer = None
    ip_enrichment = None
    threat_mapping = None
    dashboard_service = None
    report_generator = None

@app.get("/")
async def root():
    return {
        "message": "AI Log Security Analyzer API - Pure AI Threat Detection", 
        "status": "running",
        "version": "2.0.0",
        "features": [
            "AI-powered threat detection",
            "No hardcoded patterns",
            "Intelligent pattern recognition",
            "Comprehensive security analysis"
        ]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now(),
        "ai_service": "available" if log_analyzer else "unavailable"
    }

@app.post("/analyze/text", response_model=AnalysisResponse)
async def analyze_log_text(request: LogAnalysisRequest):
    """Analyze log content directly from text input using AI"""
    if not log_analyzer:
        raise HTTPException(
            status_code=500, 
            detail="AI Log analyzer not initialized - check GROQ_API_KEY configuration"
        )
    
    try:
        log_content = request.log_content
        
        # Use AI to detect threats 
        threats = log_analyzer.detect_threats(log_content)
        
        # Get comprehensive AI analysis
        log_sample = log_content[:6000] if len(log_content) > 6000 else log_content
        ai_analysis = log_analyzer.get_ai_analysis(log_sample)
        
        # Calculate AI-based risk level
        risk_level = log_analyzer.calculate_risk_level(threats)
        
        return AnalysisResponse(
            threats_detected=threats,
            ai_analysis=ai_analysis,
            total_lines=len(log_content.splitlines()),
            analysis_time=datetime.now(),
            risk_level=risk_level
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Analysis failed: {str(e)}")

@app.post("/analyze/file", response_model=AnalysisResponse)
async def analyze_log_file(file: UploadFile = File(...)):
    """Analyze uploaded log file using AI"""
    if not log_analyzer:
        raise HTTPException(
            status_code=500, 
            detail="AI Log analyzer not initialized - check GROQ_API_KEY configuration"
        )
    
    try:
        # Validate and read file
        FileHandler.validate_file(file)
        log_content, file_size = await FileHandler.read_file_content(file)
        
        print(f"📁 Analyzing file: {file.filename} ({file_size} bytes)")
        
        # Use AI to detect threats
        threats = log_analyzer.detect_threats(log_content)
        
        # Get comprehensive AI analysis
        log_sample = log_content[:6000] if len(log_content) > 6000 else log_content
        ai_analysis = log_analyzer.get_ai_analysis(log_sample)
        
        # Calculate AI-based risk level
        risk_level = log_analyzer.calculate_risk_level(threats)
        
        print(f"✅ Analysis complete: {len(threats)} threats detected, Risk: {risk_level}")
        
        return AnalysisResponse(
            threats_detected=threats,
            ai_analysis=ai_analysis,
            total_lines=len(log_content.splitlines()),
            analysis_time=datetime.now(),
            risk_level=risk_level
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI Analysis failed: {str(e)}")

@app.post("/analyze/patterns")
async def analyze_log_patterns(request: LogAnalysisRequest):
    """Analyze log patterns and identify suspicious behavior using AI"""
    if not log_analyzer:
        raise HTTPException(
            status_code=500, 
            detail="AI Log analyzer not initialized - check GROQ_API_KEY configuration"
        )
    
    try:
        log_content = request.log_content
        
        # Get AI pattern analysis
        pattern_analysis = log_analyzer.analyze_log_patterns(log_content)
        
        return {
            "status": "success",
            "analysis_time": datetime.now(),
            "pattern_analysis": pattern_analysis
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pattern analysis failed: {str(e)}")

@app.post("/upload", response_model=UploadResponse)
async def upload_file_info(file: UploadFile = File(...)):
    """Get information about uploaded file without analysis"""
    try:
        FileHandler.validate_file(file)
        _, file_size = await FileHandler.read_file_content(file)
        
        return UploadResponse(
            message="File uploaded successfully - Ready for AI analysis",
            filename=file.filename,
            file_size=file_size
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

# New endpoints for enhanced features

@app.post("/enrich/ips")
async def enrich_ips_from_logs(request: LogAnalysisRequest):
    """Extract and enrich IP addresses from log content"""
    if not ip_enrichment:
        raise HTTPException(
            status_code=500, 
            detail="IP Enrichment service not initialized"
        )
    
    try:
        log_content = request.log_content
        enriched_ips = ip_enrichment.create_enriched_ip_report(log_content)
        
        return {
            "status": "success",
            "analysis_time": datetime.now(),
            "ip_count": len(enriched_ips),
            "enriched_ips": enriched_ips
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP enrichment failed: {str(e)}")

@app.post("/map/frameworks")
async def map_to_security_frameworks(request: LogAnalysisRequest):
    """Map detected threats to MITRE ATT&CK and OWASP Top 10 frameworks"""
    if not log_analyzer or not threat_mapping:
        raise HTTPException(
            status_code=500, 
            detail="Required services not initialized"
        )
    
    try:
        log_content = request.log_content
        
        # Detect threats first
        threats = log_analyzer.detect_threats(log_content)
        
        # Map threats to frameworks
        framework_mapping = threat_mapping.map_threats_to_frameworks(threats, log_content)
        
        return {
            "status": "success",
            "analysis_time": datetime.now(),
            "threat_count": len(threats),
            "framework_mapping": framework_mapping
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Framework mapping failed: {str(e)}")

@app.post("/dashboard/data")
async def generate_dashboard_data(request: LogAnalysisRequest):
    """Generate data for visual dashboard"""
    if not log_analyzer or not dashboard_service:
        raise HTTPException(
            status_code=500, 
            detail="Required services not initialized"
        )
    
    try:
        log_content = request.log_content
        
        # Detect threats first
        threats = log_analyzer.detect_threats(log_content)
        
        # Generate dashboard data
        dashboard_data = dashboard_service.generate_dashboard_data(log_content, threats)
        
        return {
            "status": "success",
            "analysis_time": datetime.now(),
            "dashboard_data": dashboard_data
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dashboard data generation failed: {str(e)}")

@app.post("/report/generate")
async def generate_forensic_report(request: LogAnalysisRequest):
    """Generate comprehensive forensic report"""
    if not log_analyzer or not report_generator:
        raise HTTPException(
            status_code=500, 
            detail="Required services not initialized"
        )
    
    try:
        log_content = request.log_content
        
        # Detect threats
        threats = log_analyzer.detect_threats(log_content)
        
        # Get AI analysis
        log_sample = log_content[:6000] if len(log_content) > 6000 else log_content
        ai_analysis = log_analyzer.get_ai_analysis(log_sample)
        
        # Generate report
        report = await report_generator.generate_forensic_report(log_content, threats, ai_analysis)
        
        return {
            "status": "success",
            "analysis_time": datetime.now(),
            "report_id": report.report_id,
            "report": report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/report/{report_id}")
async def get_forensic_report(report_id: str):
    """Retrieve a previously generated forensic report"""
    if not report_generator:
        raise HTTPException(
            status_code=500, 
            detail="Report Generator service not initialized"
        )
    
    try:
        report = await report_generator.get_report(report_id)
        
        if not report:
            raise HTTPException(status_code=404, detail=f"Report with ID {report_id} not found")
        
        return {
            "status": "success",
            "report": report
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving report: {str(e)}")

@app.get("/reports/list")
async def list_forensic_reports():
    """List all available forensic reports"""
    if not report_generator:
        raise HTTPException(
            status_code=500, 
            detail="Report Generator service not initialized"
        )
    
    try:
        reports = await report_generator.list_reports()
        
        return {
            "status": "success",
            "report_count": len(reports),
            "reports": reports
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing reports: {str(e)}")

# Update API info endpoint to include new features
@app.get("/api/info")
async def get_api_info():
    """Get information about the AI analyzer capabilities"""
    return {
        "service": "AI Log Security Analyzer",
        "version": "2.1.0",  # Updated version
        "ai_powered": True,
        "threat_detection": {
            "method": "AI-based pattern recognition",
            "hardcoded_patterns": False,
            "supported_threats": [
                "BRUTE_FORCE",
                "SQL_INJECTION", 
                "XSS_ATTEMPT",
                "DIRECTORY_TRAVERSAL",
                "ADMIN_PROBING",
                "SUSPICIOUS_AGENT",
                "DDoS_ATTACK",
                "MALWARE_DOWNLOAD",
                "PORT_SCANNING",
                "COMMAND_INJECTION",
                "And many more detected intelligently by AI"
            ]
        },
        "analysis_features": [
            "Intelligent threat detection",
            "Pattern recognition",
            "Risk assessment",
            "Security recommendations",
            "Attack timeline analysis",
            "Coordinated attack detection",
            "GeoIP lookup and threat enrichment",
            "MITRE ATT&CK framework mapping",
            "OWASP Top 10 vulnerability mapping",
            "Visual dashboard data preparation",
            "Comprehensive forensic reporting",
            "Unified comprehensive analysis",  # New feature
            "Threat actor profiling",  # New feature
            "Automated security recommendations"  # New feature
        ],
        "supported_formats": [".log", ".txt", ".json"],
        "ai_model": "Powered by Groq AI"
    }

@app.post("/analyze/comprehensive", response_model=None)
async def comprehensive_analysis(file: UploadFile = File(...)):
    """Comprehensive analysis of uploaded log file with all enhanced features"""
    if not log_analyzer or not ip_enrichment or not threat_mapping or not dashboard_service or not report_generator:
        raise HTTPException(
            status_code=500, 
            detail="Required services not initialized"
        )
    
    try:
        # Validate and read file
        FileHandler.validate_file(file)
        log_content, file_size = await FileHandler.read_file_content(file)
        
        print(f"📁 Analyzing file: {file.filename} ({file_size} bytes)")
        
        # Use AI to detect threats
        threats = log_analyzer.detect_threats(log_content)
        
        # Get comprehensive AI analysis
        log_sample = log_content[:6000] if len(log_content) > 6000 else log_content
        ai_analysis = log_analyzer.get_ai_analysis(log_sample)
        
        # Calculate AI-based risk level
        risk_level = log_analyzer.calculate_risk_level(threats)
        
        # Extract and enrich IPs
        enriched_ips = ip_enrichment.create_enriched_ip_report(log_content)
        
        # Map threats to security frameworks
        framework_mapping = threat_mapping.map_threats_to_frameworks(threats, log_content)
        
        # Generate dashboard data
        dashboard_data = dashboard_service.generate_dashboard_data(log_content, threats)
        
        # Generate threat actor profiles (group by IP)
        threat_actors = []
        for ip in enriched_ips:
            if ip.geo_data.is_threat or any(event for event in ip.associated_events if any(threat.type in event for threat in threats)):
                actor = {
                    "identifier": ip.ip,
                    "location": f"{ip.geo_data.city}, {ip.geo_data.country}" if ip.geo_data.city else ip.geo_data.country,
                    "threat_score": ip.geo_data.threat_score,
                    "activity": ip.associated_events[:5] if ip.associated_events else ["Unknown activity"],
                    "threat_types": [threat.type for threat in threats if any(threat.type in event for event in ip.associated_events)],
                    "isp": ip.geo_data.isp,
                    "occurrences": ip.occurrences
                }
                threat_actors.append(actor)
        
        # Generate auto recommendations
        recommendations = []
        
        # IP blocking recommendations
        for ip in enriched_ips:
            if ip.geo_data.is_threat or ip.geo_data.threat_score and ip.geo_data.threat_score > 50:
                recommendations.append({
                    "type": "block_ip",
                    "target": ip.ip,
                    "reason": f"Suspicious IP with threat score {ip.geo_data.threat_score}",
                    "priority": "HIGH" if ip.geo_data.threat_score and ip.geo_data.threat_score > 80 else "MEDIUM"
                })
        
        # WAF recommendations based on attack types
        attack_types = set(threat.type for threat in threats)
        for attack_type in attack_types:
            waf_rule = None
            priority = "MEDIUM"
            
            if "SQL_INJECTION" in attack_type:
                waf_rule = "Enable SQL injection protection rules"
                priority = "HIGH"
            elif "XSS" in attack_type:
                waf_rule = "Enable cross-site scripting (XSS) protection"
                priority = "HIGH"
            elif "TRAVERSAL" in attack_type or "PATH" in attack_type:
                waf_rule = "Enable path traversal protection"
                priority = "HIGH"
            elif "BRUTE_FORCE" in attack_type:
                waf_rule = "Implement rate limiting and account lockout policies"
                priority = "MEDIUM"
            
            if waf_rule:
                recommendations.append({
                    "type": "waf_rule",
                    "action": waf_rule,
                    "reason": f"Detected {attack_type} attacks",
                    "priority": priority
                })
        
        # Framework-based recommendations
        for technique in framework_mapping.mitre_techniques:
            recommendations.append({
                "type": "mitre_control",
                "action": f"Implement controls for {technique.name}",
                "reference": technique.url,
                "reason": f"Detected {technique.technique_id} technique",
                "priority": technique.severity
            })
        
        # Combine everything into a single comprehensive response
        comprehensive_result = {
            "status": "success",
            "analysis_time": datetime.now(),
            "file_info": {
                "filename": file.filename,
                "size": file_size,
                "total_lines": len(log_content.splitlines())
            },
            "threats": {
                "detected": threats,
                "risk_level": risk_level,
                "ai_analysis": ai_analysis
            },
            "ip_enrichment": {
                "total_ips": len(enriched_ips),
                "enriched_ips": enriched_ips
            },
            "security_frameworks": framework_mapping,
            "dashboard_data": dashboard_data,
            "threat_actors": threat_actors,
            "recommendations": recommendations
        }
        
        print(f"✅ Comprehensive analysis complete: {len(threats)} threats detected, {len(enriched_ips)} IPs enriched")
        
        return comprehensive_result
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Comprehensive analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AI Log Security Analyzer...")
    print("🤖 Using pure AI for threat detection - no hardcoded patterns!")
    uvicorn.run(app, host="0.0.0.0", port=8000)