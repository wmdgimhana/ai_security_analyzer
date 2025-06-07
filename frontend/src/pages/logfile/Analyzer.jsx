import React, { useState, useEffect } from "react";
import {
  FiUploadCloud,
  FiShield,
  FiClock,
  FiFileText,
  FiAlertTriangle,
} from "react-icons/fi";
import {
  analyzeLogFile,
  analyzeLogText,
  uploadFile,
} from "../../functions/logAnalyzer";

const Analyzer = () => {
  const [logData, setLogData] = useState(null);
  const [fileName, setFileName] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [animateResults, setAnimateResults] = useState(false);
  const [error, setError] = useState(null);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setFileName(file.name);
    setIsAnalyzing(true);
    setAnimateResults(false);
    setError(null);

    try {
      // Analyze the uploaded file using the API
      const result = await analyzeLogFile(file);

      setLogData(result);
      setIsAnalyzing(false);
      setTimeout(() => setAnimateResults(true), 100);
    } catch (error) {
      console.error("Analysis failed:", error);
      setError(error.message || "Failed to analyze the file");
      setIsAnalyzing(false);
    }
  };

  const handleTextAnalysis = async (logText) => {
    if (!logText.trim()) return;

    setIsAnalyzing(true);
    setAnimateResults(false);
    setError(null);

    try {
      const result = await analyzeLogText(logText);

      setLogData(result);
      setIsAnalyzing(false);
      setTimeout(() => setAnimateResults(true), 100);
    } catch (error) {
      console.error("Analysis failed:", error);
      setError(error.message || "Failed to analyze the text");
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (level) => {
    switch (level) {
      case "HIGH":
        return "text-red-400";
      case "MEDIUM":
        return "text-yellow-400";
      case "LOW":
        return "text-green-400";
      default:
        return "text-gray-400";
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "HIGH":
        return "bg-gradient-to-r from-red-500/20 to-red-600/30 border-red-500/50";
      case "MEDIUM":
        return "bg-gradient-to-r from-yellow-500/20 to-orange-500/30 border-yellow-500/50";
      case "LOW":
        return "bg-gradient-to-r from-green-500/20 to-emerald-500/30 border-green-500/50";
      default:
        return "bg-gradient-to-r from-gray-500/20 to-gray-600/30 border-gray-500/50";
    }
  };

  return (
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
            Basic Log File Analyzer
          </h1>
          <p className="text-gray-400 text-lg poppins-light">
            AI-powered security analysis
          </p>
        </div>

        <div className="flex justify-center items-center pt-[100px] pb-[100px] flex-col gap-12">
          <div>
            <div className="input-div">
              <input
                className="input"
                name="file"
                type="file"
                accept=".log,.txt,.json"
                onChange={handleFileUpload}
                disabled={isAnalyzing}
              />
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="1em"
                height="1em"
                stroke-linejoin="round"
                stroke-linecap="round"
                viewBox="0 0 24 24"
                stroke-width="2"
                fill="none"
                stroke="currentColor"
                className="icon"
              >
                <polyline points="16 16 12 12 8 16"></polyline>
                <line y2="21" x2="12" y1="12" x1="12"></line>
                <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"></path>
                <polyline points="16 16 12 12 8 16"></polyline>
              </svg>
            </div>
          </div>

          <div className="text-center">
            <span className="text-xl text-white font-medium">
              {fileName || "Click to upload your log file"}
            </span>
            <div className="text-sm text-gray-400 mt-2">
              Supports .log, .txt, .json files
            </div>
            {fileName && !isAnalyzing && (
              <div className="text-sm text-[#dd6317] mt-2 animate-pulse">
                ✓ File selected: Ready to analyze
              </div>
            )}
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

        {/* Loading Animation */}
        {isAnalyzing && (
          <div className="mb-12 animate-fade-in">
            <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl">
              <div className="flex flex-col items-center gap-6">
                <div className="relative">
                  <div className="w-16 h-16 border-4 border-[#dd6317]/30 border-t-[#dd6317] rounded-full animate-spin"></div>
                  <FiShield className="absolute inset-0 m-auto text-2xl text-[#dd6317] animate-pulse" />
                </div>
                <h3 className="text-xl font-semibold poppins-bold">
                  Analyzing Security Threats...
                </h3>
                <p className="text-gray-400 poppins-light">
                  AI is processing your log file
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Results Section */}
        {logData && !isAnalyzing && (
          <div
            className={`space-y-8 transition-all duration-1000 ${
              animateResults
                ? "opacity-100 translate-y-0"
                : "opacity-0 translate-y-8"
            }`}
          >
            {/* Threats Section */}
            <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
              <div className="flex items-center gap-3 mb-6">
                <FiAlertTriangle className="text-2xl text-[#dd6317]" />
                <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                  Threats Detected
                </h2>
              </div>
              <div className="space-y-4">
                {logData.threats_detected &&
                logData.threats_detected.length > 0 ? (
                  logData.threats_detected.map((threat, index) => (
                    <div
                      key={index}
                      className={`p-6 rounded-xl ${getSeverityColor(
                        threat.severity
                      )} border backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg`}
                      style={{
                        animationDelay: `${index * 200}ms`,
                        animation: animateResults
                          ? "slideInLeft 0.6s ease-out forwards"
                          : "none",
                      }}
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div className="font-bold text-lg text-white poppins-regular">
                          {threat.type.replace(/_/g, " ")}
                        </div>
                        <div
                          className={`px-3 py-1 rounded-full text-xs poppins-light ${getSeverityColor(
                            threat.severity
                          )}`}
                        >
                          {threat.severity}
                        </div>
                      </div>
                      <p className="text-gray-300 mb-2 poppins-light text-[13px]">
                        {threat.description}
                      </p>
                      <div className="text-sm text-gray-400">
                        <span className="bg-white/10 px-2 py-1 rounded poppins-medium text-[12px]">
                          Count: {threat.count}
                        </span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-gray-400">
                    <FiShield className="text-4xl mx-auto mb-3 text-green-400" />
                    <p className="text-lg">
                      No threats detected in the log file
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* AI Analysis Section */}
            <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg">
                  <FiShield className="text-xl text-white" />
                </div>
                <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                  AI Security Analysis
                </h2>
              </div>
              <div className="bg-black/20 rounded-xl p-6 border border-white/10">
                <div
                  className="text-gray-300 leading-relaxed poppins-medium text-[15px]"
                  dangerouslySetInnerHTML={{
                    __html: logData.ai_analysis
                      ? logData.ai_analysis.replace(/\n/g, "<br>")
                      : "No analysis available",
                  }}
                />
              </div>
            </div>

            {/* Metadata Section */}
            <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
              <div className="flex items-center gap-3 mb-6">
                <FiFileText className="text-2xl text-[#dd6317]" />
                <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                  Analysis Summary
                </h2>
              </div>
              <div className="grid md:grid-cols-3 gap-6">
                <div className="bg-gradient-to-br from-blue-500/10 to-blue-600/20 p-6 rounded-xl border border-blue-500/30 transform transition-all duration-300 hover:scale-105">
                  <div className="flex items-center gap-3 mb-2">
                    <FiFileText className="text-blue-400" />
                    <span className="text-gray-400 poppins-medium">
                      Total Lines
                    </span>
                  </div>
                  <div className="text-2xl font-bold text-white poppins-bold">
                    {logData.total_lines || 0}
                  </div>
                </div>

                <div className="bg-gradient-to-br from-purple-500/10 to-purple-600/20 p-6 rounded-xl border border-purple-500/30 transform transition-all duration-300 hover:scale-105">
                  <div className="flex items-center gap-3 mb-2">
                    <FiClock className="text-purple-400" />
                    <span className="text-gray-400 poppins-medium">
                      Analysis Time
                    </span>
                  </div>
                  <div className="text-lg font-semibold text-white poppins-bold">
                    {logData.analysis_time
                      ? new Date(logData.analysis_time).toLocaleString()
                      : "N/A"}
                  </div>
                </div>

                <div className="bg-gradient-to-br from-orange-500/10 to-red-500/20 p-6 rounded-xl border border-orange-500/30 transform transition-all duration-300 hover:scale-105">
                  <div className="flex items-center gap-3 mb-2">
                    <FiShield className="text-orange-400" />
                    <span className="text-gray-400 poppins-medium">
                      Risk Level
                    </span>
                  </div>
                  <div
                    className={`text-2xl font-bold poppins-bold ${getRiskColor(
                      logData.risk_level
                    )}`}
                  >
                    {logData.risk_level || "UNKNOWN"}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes slideInLeft {
          from {
            opacity: 0;
            transform: translateX(-50px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }

        .animate-fade-in {
          animation: fadeIn 0.8s ease-out;
        }
      `}</style>
    </div>
  );
};

export default Analyzer;
