import React, { useState } from "react";
import Sidebar from "../../components/sidebar/Sidebar";
import { FiUploadCloud, FiGlobe, FiAlertTriangle, FiMapPin } from "react-icons/fi";
import { enrichIpsFromLogs } from "../../functions/logAnalyzer";

const IpEnrichment = () => {
  const [logContent, setLogContent] = useState("");
  const [enrichmentData, setEnrichmentData] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [animateResults, setAnimateResults] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!logContent.trim()) return;

    setIsAnalyzing(true);
    setAnimateResults(false);
    setError(null);

    try {
      const result = await enrichIpsFromLogs(logContent);
      setEnrichmentData(result);
      setIsAnalyzing(false);
      setTimeout(() => setAnimateResults(true), 100);
    } catch (error) {
      console.error("IP enrichment failed:", error);
      setError(error.message || "Failed to enrich IP data");
      setIsAnalyzing(false);
    }
  };

  const getThreatColor = (score) => {
    if (!score && score !== 0) return "text-gray-400";
    if (score > 80) return "text-red-400";
    if (score > 50) return "text-yellow-400";
    return "text-green-400";
  };

  return (
    <div className="w-screen h-screen flex overflow-x-hidden overflow-y-hidden">
      <div className="flex-[1] w-full h-full bg-[#1e1f28]">
        <Sidebar />
      </div>
      <div className="flex-[6] w-full h-full bg-[#16171d] overflow-y-auto">
        <div className="min-h-screen bg-gradient-to-br from-[#0f0f15] via-[#16171d] to-[#1a1b23] text-white p-6">
          {/* Animated Background Elements */}
          <div className="fixed inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-gradient-to-r from-[#dd6317]/10 to-orange-600/10 rounded-full blur-3xl animate-pulse"></div>
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-gradient-to-r from-amber-500/10 to-[#dd6317]/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
          </div>

          <div className="relative z-10 max-w-6xl mx-auto">
            {/* Header */}
            <div className="text-center mb-12 animate-fade-in">
              <h1 className="text-5xl poppins-bold font-bold mb-4 bg-gradient-to-r from-[#dd6317] via-orange-400 to-amber-300 bg-clip-text text-transparent leading-normal pb-1">
                IP Enrichment
              </h1>
              <p className="text-gray-400 text-lg poppins-light">
                Extract and analyze IP addresses from log files
              </p>
            </div>

            {/* Input Section */}
            <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm mb-8">
              <div className="flex items-center gap-3 mb-6">
                <FiGlobe className="text-2xl text-[#dd6317]" />
                <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                  Enter Log Content
                </h2>
              </div>
              
              <textarea
                className="w-full h-64 bg-black/20 text-white p-4 rounded-xl border border-white/10 focus:outline-none focus:border-[#dd6317]/50 transition-all duration-300 poppins-light"
                placeholder="Paste your log content here..."
                value={logContent}
                onChange={(e) => setLogContent(e.target.value)}
                disabled={isAnalyzing}
              />
              
              <div className="mt-4 flex justify-end">
                <button
                  className="px-6 py-3 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg text-white font-semibold hover:from-orange-500 hover:to-[#dd6317] transition-all duration-300 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  onClick={handleAnalyze}
                  disabled={!logContent.trim() || isAnalyzing}
                >
                  {isAnalyzing ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <FiGlobe />
                      <span>Enrich IPs</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <div className="mb-12 animate-fade-in">
                <div className="bg-gradient-to-br from-red-900/20 via-red-800/20 to-red-900/20 rounded-2xl p-8 border border-red-500/30 shadow-2xl">
                  <div className="flex items-center gap-3 mb-2">
                    <FiAlertTriangle className="text-2xl text-red-400" />
                    <h3 className="text-xl font-semibold text-red-400">
                      Analysis Error
                    </h3>
                  </div>
                  <p className="text-red-300">{error}</p>
                </div>
              </div>
            )}

            {/* Results Section */}
            {enrichmentData && !isAnalyzing && (
              <div
                className={`space-y-8 transition-all duration-1000 ${animateResults ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}
              >
                <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex items-center gap-3 mb-6">
                    <FiGlobe className="text-2xl text-[#dd6317]" />
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      IP Enrichment Results
                    </h2>
                  </div>
                  
                  <div className="mb-4 p-4 bg-black/20 rounded-xl border border-white/10">
                    <div className="flex justify-between items-center">
                      <div className="text-gray-300 poppins-medium">
                        <span className="text-[#dd6317]">Total IPs Detected:</span> {enrichmentData.ip_count || 0}
                      </div>
                      <div className="text-gray-300 poppins-medium">
                        <span className="text-[#dd6317]">Analysis Time:</span> {new Date(enrichmentData.analysis_time).toLocaleString()}
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-6">
                    {enrichmentData.enriched_ips && enrichmentData.enriched_ips.length > 0 ? (
                      enrichmentData.enriched_ips.map((ip, index) => (
                        <div
                          key={index}
                          className={`p-6 rounded-xl bg-gradient-to-br ${ip.geo_data.is_threat ? "from-red-500/10 to-red-600/20 border-red-500/30" : "from-blue-500/10 to-blue-600/20 border-blue-500/30"} border backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg`}
                          style={{
                            animationDelay: `${index * 200}ms`,
                            animation: animateResults ? "slideInLeft 0.6s ease-out forwards" : "none",
                          }}
                        >
                          <div className="flex flex-col md:flex-row md:items-center justify-between mb-3 gap-4">
                            <div>
                              <div className="font-bold text-lg text-white poppins-regular flex items-center gap-2">
                                <FiGlobe className="text-blue-400" />
                                {ip.ip}
                                {ip.geo_data.is_threat && (
                                  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-red-500/20 text-red-400 border border-red-500/30">
                                    <FiAlertTriangle className="mr-1" /> Threat
                                  </span>
                                )}
                              </div>
                              <div className="text-gray-400 text-sm flex items-center gap-1 mt-1">
                                <FiMapPin className="text-gray-500" />
                                {ip.geo_data.city ? `${ip.geo_data.city}, ${ip.geo_data.country}` : ip.geo_data.country || "Location Unknown"}
                              </div>
                            </div>
                            
                            <div className="flex items-center gap-3">
                              <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                <div className="text-xs text-gray-400">Occurrences</div>
                                <div className="text-lg font-bold text-white">{ip.occurrences}</div>
                              </div>
                              
                              <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                <div className="text-xs text-gray-400">Threat Score</div>
                                <div className={`text-lg font-bold ${getThreatColor(ip.geo_data.threat_score)}`}>
                                  {ip.geo_data.threat_score !== undefined ? ip.geo_data.threat_score : "N/A"}
                                </div>
                              </div>
                            </div>
                          </div>
                          
                          {ip.geo_data.isp && (
                            <div className="mb-3 text-sm">
                              <span className="text-gray-400">ISP:</span> <span className="text-gray-300">{ip.geo_data.isp}</span>
                            </div>
                          )}
                          
                          {ip.geo_data.threat_type && (
                            <div className="mb-3 text-sm">
                              <span className="text-gray-400">Threat Type:</span> <span className="text-red-300">{ip.geo_data.threat_type}</span>
                            </div>
                          )}
                          
                          {ip.associated_events && ip.associated_events.length > 0 && (
                            <div className="mt-4">
                              <div className="text-sm font-semibold text-gray-300 mb-2">Associated Events:</div>
                              <div className="max-h-32 overflow-y-auto bg-black/20 rounded-lg border border-white/5 p-3">
                                <ul className="space-y-1">
                                  {ip.associated_events.map((event, eventIndex) => (
                                    <li key={eventIndex} className="text-xs text-gray-400 truncate">{event}</li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <FiGlobe className="text-4xl mx-auto mb-3 text-blue-400" />
                        <p className="text-lg">No IP addresses detected in the log content</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IpEnrichment;