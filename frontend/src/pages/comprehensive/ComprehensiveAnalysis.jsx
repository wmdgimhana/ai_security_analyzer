import React, { useState } from "react";
import Sidebar from "../../components/sidebar/Sidebar";
import {
  FiUploadCloud,
  FiShield,
  FiAlertTriangle,
  FiBarChart2,
  FiGlobe,
  FiClock,
  FiFileText,
  FiUsers,
  FiLock,
  FiMapPin,
  FiExternalLink,
} from "react-icons/fi";
import { comprehensiveAnalysis } from "../../functions/logAnalyzer";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  TimeScale,
} from "chart.js";
import { Pie, Bar } from "react-chartjs-2";
import "chart.js/auto";

// Register ChartJS components
ChartJS.register(
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  TimeScale
);

const ComprehensiveAnalysis = () => {
  const [file, setFile] = useState(null);
  const [fileName, setFileName] = useState("");
  const [analysisData, setAnalysisData] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [animateResults, setAnimateResults] = useState(false);
  const [error, setError] = useState(null);

  const handleFileUpload = async (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    setFile(selectedFile);
    setFileName(selectedFile.name);
    setIsAnalyzing(false);
    setAnimateResults(false);
    setError(null);
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setIsAnalyzing(true);
    setAnimateResults(false);
    setError(null);

    try {
      const result = await comprehensiveAnalysis(file);
      console.log("Comprehensive analysis result:", result);
      console.log("Dashboard data:", result.dashboard_data);
      console.log(
        "Threat type distribution:",
        result.dashboard_data?.threat_type_distribution
      );
      console.log("Threats by IP:", result.dashboard_data?.threats_by_ip);
      setAnalysisData(result);
      setIsAnalyzing(false);
      setTimeout(() => setAnimateResults(true), 100);
    } catch (error) {
      console.error("Comprehensive analysis failed:", error);
      setError(error.message || "Failed to perform comprehensive analysis");
      setIsAnalyzing(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "HIGH":
        return "bg-gradient-to-r from-red-500/20 to-red-600/30 border-red-500/50 text-red-400";
      case "MEDIUM":
        return "bg-gradient-to-r from-yellow-500/20 to-orange-500/30 border-yellow-500/50 text-yellow-400";
      case "LOW":
        return "bg-gradient-to-r from-green-500/20 to-emerald-500/30 border-green-500/50 text-green-400";
      default:
        return "bg-gradient-to-r from-gray-500/20 to-gray-600/30 border-gray-500/50 text-gray-400";
    }
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
                Comprehensive Security Analysis
              </h1>
              <p className="text-gray-400 text-lg poppins-light">
                Advanced multi-layered security analysis with AI insights
              </p>
            </div>

            {/* File Upload Section */}
            <div className="pt-[90px]">
              <div className="flex flex-col items-center justify-center py-6">
                <div className="input-div mb-4">
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
                    strokeLinejoin="round"
                    strokeLinecap="round"
                    viewBox="0 0 24 24"
                    strokeWidth="2"
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

                <div className="text-center mb-4 mt-[50px]">
                  <span className="text-xl text-white font-medium">
                    {fileName || "Click to upload your log file"}
                  </span>
                  <div className="text-sm text-gray-400 mt-2">
                    Supports .log, .txt, .json files
                  </div>
                </div>

                <button
                  className="px-6 py-3 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg cursor-pointer text-white font-semibold hover:from-orange-500 hover:to-[#dd6317] transition-all duration-300 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed mt-[30px]"
                  onClick={handleAnalyze}
                  disabled={!file || isAnalyzing}
                >
                  {isAnalyzing ? (
                    <>
                      <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <FiShield />
                      <span>Run Comprehensive Analysis</span>
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

            {/* Loading Animation */}
            {isAnalyzing && (
              <div className="mb-12 animate-fade-in">
                <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl">
                  <div className="flex flex-col items-center gap-6">
                    <div className="relative">
                      <div className="w-16 h-16 border-4 border-[#dd6317]/30 border-t-[#dd6317] rounded-full animate-spin"></div>
                      <FiShield className="absolute inset-0 m-auto text-2xl text-[#dd6317] animate-pulse" />
                    </div>
                    <h3 className="text-xl font-semibold poppins-bold">
                      Running Comprehensive Analysis...
                    </h3>
                    <p className="text-gray-400 poppins-light">
                      This may take a minute as we analyze multiple security
                      aspects
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Results Section */}
            {analysisData && !isAnalyzing && (
              <div
                className={`space-y-8 transition-all duration-1000 ${
                  animateResults
                    ? "opacity-100 translate-y-0"
                    : "opacity-0 translate-y-8"
                }`}
              >
                {/* Executive Summary */}
                <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg">
                      <FiShield className="text-xl text-white" />
                    </div>
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      Executive Summary
                    </h2>
                  </div>
                  <div className="bg-black/20 rounded-xl p-6 border border-white/10">
                    <div className="text-gray-300 leading-relaxed poppins-medium text-[15px]">
                      {analysisData.threats?.ai_analysis ||
                        "No executive summary available"}
                    </div>
                  </div>
                </div>

                {/* Dashboard Data Section */}
                {analysisData.dashboard_data && (
                  <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                    <div className="flex items-center gap-3 mb-6">
                      <FiBarChart2 className="text-2xl text-[#dd6317]" />
                      <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                        Security Dashboard
                      </h2>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                      {/* Threat Type Distribution */}
                      <div className="bg-black/20 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-semibold text-white mb-4">
                          Threat Type Distribution
                        </h3>
                        <div className="h-64">
                          {analysisData.dashboard_data.attack_distribution && (
                            <Pie
                              data={{
                                labels: Object.keys(
                                  analysisData.dashboard_data
                                    .attack_distribution
                                ),
                                datasets: [
                                  {
                                    data: Object.values(
                                      analysisData.dashboard_data
                                        .attack_distribution
                                    ),
                                    backgroundColor: [
                                      "rgba(221, 99, 23, 0.7)",
                                      "rgba(255, 159, 64, 0.7)",
                                      "rgba(255, 205, 86, 0.7)",
                                      "rgba(75, 192, 192, 0.7)",
                                      "rgba(54, 162, 235, 0.7)",
                                      "rgba(153, 102, 255, 0.7)",
                                      "rgba(201, 203, 207, 0.7)",
                                    ],
                                    borderColor: [
                                      "rgb(221, 99, 23)",
                                      "rgb(255, 159, 64)",
                                      "rgb(255, 205, 86)",
                                      "rgb(75, 192, 192)",
                                      "rgb(54, 162, 235)",
                                      "rgb(153, 102, 255)",
                                      "rgb(201, 203, 207)",
                                    ],
                                    borderWidth: 1,
                                  },
                                ],
                              }}
                              options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                  legend: {
                                    position: "right",
                                    labels: {
                                      color: "white",
                                      font: {
                                        family: "Poppins",
                                      },
                                    },
                                  },
                                  tooltip: {
                                    backgroundColor: "rgba(0, 0, 0, 0.7)",
                                    titleFont: {
                                      family: "Poppins",
                                      size: 14,
                                    },
                                    bodyFont: {
                                      family: "Poppins",
                                      size: 13,
                                    },
                                  },
                                },
                              }}
                            />
                          )}
                        </div>
                      </div>

                      {/* Threats by IP */}
                      <div className="bg-black/20 rounded-xl p-6 border border-white/10">
                        <h3 className="text-xl font-semibold text-white mb-4">
                          Threats by IP
                        </h3>
                        <div className="h-64">
                          {analysisData.dashboard_data.ip_frequency && (
                            <Bar
                              data={{
                                labels: Object.keys(
                                  analysisData.dashboard_data.ip_frequency
                                ),
                                datasets: [
                                  {
                                    label: "Threat Count",
                                    data: Object.values(
                                      analysisData.dashboard_data.ip_frequency
                                    ),
                                    backgroundColor: "rgba(221, 99, 23, 0.7)",
                                    borderColor: "rgb(221, 99, 23)",
                                    borderWidth: 1,
                                  },
                                ],
                              }}
                              options={{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                  legend: {
                                    display: false,
                                  },
                                  tooltip: {
                                    backgroundColor: "rgba(0, 0, 0, 0.7)",
                                    titleFont: {
                                      family: "Poppins",
                                      size: 14,
                                    },
                                    bodyFont: {
                                      family: "Poppins",
                                      size: 13,
                                    },
                                  },
                                },
                                scales: {
                                  y: {
                                    beginAtZero: true,
                                    ticks: {
                                      color: "white",
                                      font: {
                                        family: "Poppins",
                                      },
                                    },
                                    grid: {
                                      color: "rgba(255, 255, 255, 0.1)",
                                    },
                                  },
                                  x: {
                                    ticks: {
                                      color: "white",
                                      font: {
                                        family: "Poppins",
                                      },
                                    },
                                    grid: {
                                      color: "rgba(255, 255, 255, 0.1)",
                                    },
                                  },
                                },
                              }}
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Threats Section */}
                <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex items-center gap-3 mb-6">
                    <FiAlertTriangle className="text-2xl text-[#dd6317]" />
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      Threats Detected
                    </h2>
                  </div>
                  <div className="space-y-4">
                    {analysisData.threats?.detected &&
                    analysisData.threats.detected.length > 0 ? (
                      analysisData.threats.detected.map((threat, index) => (
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

                {/* Threat Actors Section */}
                {analysisData.threat_actors &&
                  analysisData.threat_actors.length > 0 && (
                    <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiUsers className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          Threat Actors
                        </h2>
                      </div>
                      <div className="space-y-4">
                        {analysisData.threat_actors.map((actor, index) => (
                          <div
                            key={index}
                            className="p-6 rounded-xl bg-gradient-to-r from-purple-500/10 to-purple-600/20 border border-purple-500/30 backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg"
                          >
                            <div className="flex flex-col md:flex-row md:items-center justify-between mb-3 gap-4">
                              <div>
                                <div className="font-bold text-lg text-white poppins-regular flex items-center gap-2">
                                  {actor.identifier}
                                  {actor.threat_score > 70 && (
                                    <span className="bg-red-500/20 text-red-400 text-xs px-2 py-1 rounded-full border border-red-500/30">
                                      High Risk
                                    </span>
                                  )}
                                </div>
                                <div className="text-gray-300 mt-2 poppins-light text-sm flex items-center gap-2">
                                  <FiGlobe className="text-[#dd6317]" />
                                  {actor.location || "Unknown location"}
                                </div>
                              </div>

                              <div className="flex items-center gap-2">
                                <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                  <div className="text-xs text-gray-400">
                                    Threat Score
                                  </div>
                                  <div className="text-lg font-bold text-white">
                                    {actor.threat_score || "N/A"}
                                  </div>
                                </div>

                                <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                  <div className="text-xs text-gray-400">
                                    Occurrences
                                  </div>
                                  <div className="text-lg font-bold text-white">
                                    {actor.occurrences || "N/A"}
                                  </div>
                                </div>
                              </div>
                            </div>

                            {actor.isp && (
                              <div className="text-sm text-gray-400 mb-2">
                                <span className="text-[#dd6317]">ISP:</span>{" "}
                                {actor.isp}
                              </div>
                            )}

                            {actor.threat_types &&
                              actor.threat_types.length > 0 && (
                                <div className="mt-3">
                                  <div className="text-sm text-[#dd6317] mb-1">
                                    Threat Types:
                                  </div>
                                  <div className="flex flex-wrap gap-2">
                                    {actor.threat_types.map((type, i) => (
                                      <span
                                        key={i}
                                        className="bg-red-500/10 text-red-300 text-xs px-2 py-1 rounded border border-red-500/20"
                                      >
                                        {type.replace(/_/g, " ")}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                            {actor.activity && actor.activity.length > 0 && (
                              <div className="mt-3">
                                <div className="text-sm text-[#dd6317] mb-1">
                                  Recent Activity:
                                </div>
                                <ul className="text-xs text-gray-300 space-y-1 ml-4 list-disc">
                                  {actor.activity.map((activity, i) => (
                                    <li key={i}>{activity}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Framework Mapping Section */}
                {analysisData.security_frameworks && (
                  <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                    <div className="flex items-center gap-3 mb-6">
                      <div className="p-2 bg-gradient-to-r from-blue-500/20 to-blue-600/30 rounded-lg">
                        <FiShield className="text-xl text-blue-400" />
                      </div>
                      <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                        Security Framework Mapping
                      </h2>
                    </div>

                    {/* MITRE ATT&CK */}
                    <h3 className="text-xl font-semibold text-white mb-4">
                      MITRE ATT&CK
                    </h3>
                    <div className="space-y-4 mb-8">
                      {analysisData.security_frameworks.mitre_techniques &&
                      analysisData.security_frameworks.mitre_techniques.length >
                        0 ? (
                        analysisData.security_frameworks.mitre_techniques.map(
                          (technique, index) => (
                            <div
                              key={index}
                              className={`p-6 rounded-xl ${getSeverityColor(
                                technique.severity
                              )} border backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg`}
                            >
                              <div className="flex flex-col md:flex-row md:items-center justify-between mb-3 gap-4">
                                <div>
                                  <div className="font-bold text-lg text-white poppins-regular flex items-center gap-2">
                                    {technique.technique_id}: {technique.name}
                                  </div>
                                  <div className="text-gray-300 mt-2 poppins-light text-sm">
                                    {technique.description}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                    <div className="text-xs text-gray-400">
                                      Confidence
                                    </div>
                                    <div className="text-lg font-bold text-white">
                                      {Math.round(technique.confidence * 100)}%
                                    </div>
                                  </div>

                                  <a
                                    href={technique.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-2 bg-blue-500/20 text-blue-400 rounded-lg border border-blue-500/30 hover:bg-blue-500/30 transition-all duration-300"
                                  >
                                    <FiExternalLink />
                                  </a>
                                </div>
                              </div>
                            </div>
                          )
                        )
                      ) : (
                        <div className="text-center py-4 text-gray-400">
                          <p>No MITRE ATT&CK techniques identified</p>
                        </div>
                      )}
                    </div>

                    {/* OWASP Top 10 */}
                    <h3 className="text-xl font-semibold text-white mb-4">
                      OWASP Top 10
                    </h3>
                    <div className="space-y-4">
                      {analysisData.security_frameworks.owasp_vulnerabilities &&
                      analysisData.security_frameworks.owasp_vulnerabilities
                        .length > 0 ? (
                        analysisData.security_frameworks.owasp_vulnerabilities.map(
                          (vuln, index) => (
                            <div
                              key={index}
                              className={`p-6 rounded-xl ${getSeverityColor(
                                vuln.severity
                              )} border backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg`}
                            >
                              <div className="flex flex-col md:flex-row md:items-center justify-between mb-3 gap-4">
                                <div>
                                  <div className="font-bold text-lg text-white poppins-regular flex items-center gap-2">
                                    {vuln.owasp_id}: {vuln.name}
                                  </div>
                                  <div className="text-gray-300 mt-2 poppins-light text-sm">
                                    {vuln.description}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                    <div className="text-xs text-gray-400">
                                      Confidence
                                    </div>
                                    <div className="text-lg font-bold text-white">
                                      {Math.round(vuln.confidence * 100)}%
                                    </div>
                                  </div>

                                  <a
                                    href={vuln.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="p-2 bg-purple-500/20 text-purple-400 rounded-lg border border-purple-500/30 hover:bg-purple-500/30 transition-all duration-300"
                                  >
                                    <FiExternalLink />
                                  </a>
                                </div>
                              </div>
                            </div>
                          )
                        )
                      ) : (
                        <div className="text-center py-4 text-gray-400">
                          <p>No OWASP vulnerabilities identified</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Recommendations Section */}
                {analysisData.recommendations &&
                  analysisData.recommendations.length > 0 && (
                    <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiLock className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          Security Recommendations
                        </h2>
                      </div>
                      <div className="space-y-4">
                        {analysisData.recommendations.map((rec, index) => (
                          <div
                            key={index}
                            className={`p-6 rounded-xl bg-gradient-to-r from-green-500/10 to-emerald-600/20 border border-green-500/30 backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg`}
                          >
                            <div className="flex items-center justify-between mb-3">
                              <div className="font-bold text-lg text-white poppins-regular">
                                {rec.type === "block_ip"
                                  ? "Block IP Address"
                                  : rec.type === "waf_rule"
                                  ? "Web Application Firewall Rule"
                                  : rec.type === "mitre_control"
                                  ? "MITRE Control"
                                  : "Security Recommendation"}
                              </div>
                              <div
                                className={`px-3 py-1 rounded-full text-xs poppins-light 
                              ${
                                rec.priority === "HIGH"
                                  ? "bg-red-500/20 text-red-400 border border-red-500/30"
                                  : rec.priority === "MEDIUM"
                                  ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                                  : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                              }`}
                              >
                                {rec.priority || "MEDIUM"}
                              </div>
                            </div>

                            <div className="text-gray-300 mb-3 poppins-light text-[15px]">
                              {rec.type === "block_ip" ? (
                                <div className="flex items-center gap-2">
                                  <span className="text-[#dd6317]">
                                    Target IP:
                                  </span>
                                  <span className="bg-black/30 px-2 py-1 rounded font-mono">
                                    {rec.target}
                                  </span>
                                </div>
                              ) : rec.type === "waf_rule" ||
                                rec.type === "mitre_control" ? (
                                <div>
                                  <span className="text-[#dd6317]">
                                    Action:
                                  </span>{" "}
                                  {rec.action}
                                </div>
                              ) : null}
                            </div>

                            <div className="text-gray-300 poppins-light text-[13px]">
                              <span className="text-[#dd6317]">Reason:</span>{" "}
                              {rec.reason}
                            </div>

                            {rec.reference && (
                              <div className="mt-2 text-blue-400 text-sm hover:underline">
                                <a
                                  href={rec.reference}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  View Reference
                                </a>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* IP Enrichment Section */}
                {analysisData.ip_enrichment &&
                  analysisData.ip_enrichment.enriched_ips && (
                    <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiGlobe className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          IP Enrichment
                        </h2>
                      </div>

                      <div className="mb-4 p-4 bg-black/20 rounded-xl border border-white/10">
                        <div className="flex justify-between items-center">
                          <div className="text-gray-300 poppins-medium">
                            <span className="text-[#dd6317]">Total IPs:</span>{" "}
                            {analysisData.ip_enrichment.total_ips || 0}
                          </div>
                        </div>
                      </div>

                      <div className="space-y-4">
                        {analysisData.ip_enrichment.enriched_ips.map(
                          (ip, index) => (
                            <div
                              key={index}
                              className="p-6 rounded-xl bg-gradient-to-r from-blue-500/10 to-blue-600/20 border border-blue-500/30 backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg"
                            >
                              <div className="flex flex-col md:flex-row md:items-center justify-between mb-3 gap-4">
                                <div>
                                  <div className="font-bold text-lg text-white poppins-regular flex items-center gap-2">
                                    {ip.ip}
                                    {ip.geo_data.is_threat && (
                                      <span className="bg-red-500/20 text-red-400 text-xs px-2 py-1 rounded-full border border-red-500/30">
                                        Threat
                                      </span>
                                    )}
                                  </div>
                                  <div className="text-gray-300 mt-2 poppins-light text-sm flex items-center gap-2">
                                    <FiMapPin className="text-[#dd6317]" />
                                    {ip.geo_data.country}
                                    {ip.geo_data.city
                                      ? `, ${ip.geo_data.city}`
                                      : ""}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                    <div className="text-xs text-gray-400">
                                      Occurrences
                                    </div>
                                    <div className="text-lg font-bold text-white">
                                      {ip.occurrences}
                                    </div>
                                  </div>

                                  {ip.geo_data.threat_score !== null && (
                                    <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                                      <div className="text-xs text-gray-400">
                                        Threat Score
                                      </div>
                                      <div className="text-lg font-bold text-white">
                                        {ip.geo_data.threat_score}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>

                              {ip.geo_data.isp && (
                                <div className="text-sm text-gray-400 mb-2">
                                  <span className="text-[#dd6317]">ISP:</span>{" "}
                                  {ip.geo_data.isp}
                                </div>
                              )}

                              {ip.geo_data.threat_type && (
                                <div className="text-sm text-red-400 mb-2">
                                  <span className="text-[#dd6317]">
                                    Threat Type:
                                  </span>{" "}
                                  {ip.geo_data.threat_type}
                                </div>
                              )}

                              {ip.associated_events &&
                                ip.associated_events.length > 0 && (
                                  <div className="mt-4">
                                    <div className="text-sm font-semibold text-gray-300 mb-2">
                                      Associated Events:
                                    </div>
                                    <div className="max-h-32 overflow-y-auto bg-black/20 rounded-lg border border-white/5 p-3">
                                      <ul className="space-y-1">
                                        {ip.associated_events.map(
                                          (event, eventIndex) => (
                                            <li
                                              key={eventIndex}
                                              className="text-xs text-gray-400 truncate"
                                            >
                                              {event}
                                            </li>
                                          )
                                        )}
                                      </ul>
                                    </div>
                                  </div>
                                )}
                            </div>
                          )
                        )}
                      </div>
                    </div>
                  )}

                {/* Generate Report Button */}
                <div className="flex justify-center mt-8">
                  <button
                    className="px-8 py-4 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg text-white font-semibold hover:from-orange-500 hover:to-[#dd6317] transition-all duration-300 flex items-center gap-2 text-lg"
                    onClick={() => {
                      // Navigate to the report page or generate a new report
                      if (analysisData.report_id) {
                        window.location.href = `/reports/${analysisData.report_id}`;
                      }
                    }}
                    disabled={!analysisData.report_id}
                  >
                    <FiFileText />
                    <span>View Full Forensic Report</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ComprehensiveAnalysis;
