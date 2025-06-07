import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import Sidebar from "../../components/sidebar/Sidebar";
import {
  FiFileText,
  FiClock,
  FiAlertTriangle,
  FiServer,
  FiUsers,
  FiShield,
  FiGlobe,
  FiArrowLeft,
  FiLock,
  FiMapPin,
} from "react-icons/fi";
import { getForensicReport } from "../../functions/logAnalyzer";
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

const ReportDetail = () => {
  const { reportId } = useParams();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        setLoading(true);
        const response = await getForensicReport(reportId);
        setReport(response.report);
        console.log(response.report);

        setLoading(false);
      } catch (error) {
        console.error("Error fetching report:", error);
        setError(error.message || "Failed to fetch forensic report");
        setLoading(false);
      }
    };

    if (reportId) {
      fetchReport();
    }
  }, [reportId]);

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
            {/* Back Button */}
            <div className="mb-6">
              <Link
                to="/reports"
                className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
              >
                <FiArrowLeft />
                <span>Back to Reports</span>
              </Link>
            </div>

            {/* Header */}
            <div className="text-center mb-12 animate-fade-in">
              <h1 className="text-5xl poppins-bold font-bold mb-4 bg-gradient-to-r from-[#dd6317] via-orange-400 to-amber-300 bg-clip-text text-transparent leading-normal pb-1">
                Forensic Report
              </h1>
              <p className="text-gray-400 text-lg poppins-light">
                Detailed security analysis with actionable insights
              </p>
            </div>

            {/* Error Display */}
            {error && (
              <div className="mb-12 animate-fade-in">
                <div className="bg-gradient-to-br from-red-900/20 via-red-800/20 to-red-900/20 rounded-2xl p-8 border border-red-500/30 shadow-2xl">
                  <div className="flex items-center gap-3 mb-2">
                    <FiAlertTriangle className="text-2xl text-red-400" />
                    <h3 className="text-xl font-semibold text-red-400">
                      Error
                    </h3>
                  </div>
                  <p className="text-red-300">{error}</p>
                </div>
              </div>
            )}

            {/* Loading Animation */}
            {loading && (
              <div className="flex justify-center items-center py-20">
                <div className="relative">
                  <div className="w-16 h-16 border-4 border-[#dd6317]/30 border-t-[#dd6317] rounded-full animate-spin"></div>
                  <FiFileText className="absolute inset-0 m-auto text-2xl text-[#dd6317] animate-pulse" />
                </div>
              </div>
            )}

            {/* Report Content */}
            {report && !loading && (
              <div className="space-y-8">
                {/* Report Header */}
                <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <FiFileText className="text-[#dd6317]" />
                        <h3 className="text-xl font-semibold text-white">
                          Report ID: {report.report_id.substring(0, 8)}
                        </h3>
                      </div>
                      <div className="flex items-center gap-2 text-gray-400">
                        <FiClock />
                        <span>
                          {new Date(report.generated_at).toLocaleString()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                        <div className="text-xs text-gray-400">Threats</div>
                        <div className="text-lg font-bold text-white">
                          {report.technical_details.threat_count || 0}
                        </div>
                      </div>

                      {/* <div className="text-center px-3 py-2 bg-black/30 rounded-lg border border-white/5">
                        <div className="text-xs text-gray-400">Systems</div>
                        <div className="text-lg font-bold text-white">
                          {report.affected_systems.length}
                        </div>
                      </div> */}
                    </div>
                  </div>

                  {/* Executive Summary */}
                  <div className="bg-black/20 rounded-xl p-6 border border-white/10">
                    <h4 className="text-lg font-semibold text-[#dd6317] mb-3">
                      Executive Summary
                    </h4>
                    <div className="text-gray-300 leading-relaxed poppins-medium text-[15px]">
                      {report.executive_summary}
                    </div>
                  </div>
                </div>

                {/* Key Findings */}
                <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex items-center gap-3 mb-6">
                    <FiAlertTriangle className="text-2xl text-[#dd6317]" />
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      Key Findings
                    </h2>
                  </div>

                  <div className="space-y-2">
                    {report.key_findings.map((finding, index) => (
                      <div
                        key={index}
                        className="p-4 bg-black/20 rounded-lg border border-white/10"
                      >
                        <div className="flex items-start gap-2">
                          <div className="mt-1 text-[#dd6317]">•</div>
                          <div className="text-gray-300">{finding}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat Actors */}
                {report.threat_actors && report.threat_actors.length > 0 && (
                  <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                    <div className="flex items-center gap-3 mb-6">
                      <FiUsers className="text-2xl text-[#dd6317]" />
                      <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                        Threat Actors
                      </h2>
                    </div>

                    <div className="space-y-4">
                      {report.threat_actors.map((actor, index) => (
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

                {/* Attack Timeline */}
                {report.attack_timeline &&
                  report.attack_timeline.length > 0 && (
                    <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiClock className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          Attack Timeline
                        </h2>
                      </div>

                      <div className="relative pl-8 border-l-2 border-[#dd6317]/30 space-y-8">
                        {report.attack_timeline.map((event, index) => (
                          <div key={index} className="relative">
                            <div className="absolute -left-[41px] w-5 h-5 rounded-full bg-[#dd6317] border-4 border-[#1e1f28]"></div>
                            <div className="bg-black/20 rounded-xl p-5 border border-white/10">
                              <div className="text-sm text-gray-400 mb-2">
                                {new Date(event.timestamp).toLocaleString()}
                              </div>
                              <div className="font-semibold text-white mb-2">
                                {event.event_type}
                              </div>
                              <div className="text-gray-300 text-sm">
                                {event.description}
                              </div>
                              {event.source_ip && (
                                <div className="mt-2 text-xs bg-black/30 inline-block px-2 py-1 rounded">
                                  Source IP: {event.source_ip}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                {/* Recommendations */}
                {report.recommendations &&
                  report.recommendations.length > 0 && (
                    <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiLock className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          Security Recommendations
                        </h2>
                      </div>

                      <div className="space-y-4">
                        {report.recommendations.map((rec, index) => (
                          <div
                            key={index}
                            className="p-6 rounded-xl bg-gradient-to-r from-green-500/10 to-emerald-600/20 border border-green-500/30 backdrop-blur-sm transform transition-all duration-500 hover:scale-[1.02] hover:shadow-lg"
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

                {/* Affected Systems */}
                {report.affected_systems &&
                  report.affected_systems.length > 0 && (
                    <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                      <div className="flex items-center gap-3 mb-6">
                        <FiServer className="text-2xl text-[#dd6317]" />
                        <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                          Affected Systems
                        </h2>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {report.affected_systems.map((system, index) => (
                          <div
                            key={index}
                            className="p-4 bg-black/20 rounded-lg border border-white/10 flex items-center gap-3"
                          >
                            <FiServer className="text-[#dd6317]" />
                            <span className="text-gray-300">{system}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            )}
          </div>
        </div>
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

        .animate-fade-in {
          animation: fadeIn 0.8s ease-out;
        }
      `}</style>
    </div>
  );
};

export default ReportDetail;
