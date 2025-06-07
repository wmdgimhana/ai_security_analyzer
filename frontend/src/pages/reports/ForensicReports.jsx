import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import Sidebar from "../../components/sidebar/Sidebar";
import {
  FiFileText,
  FiClock,
  FiAlertTriangle,
  FiServer,
  FiExternalLink,
} from "react-icons/fi";
import { listForensicReports } from "../../functions/logAnalyzer";

const ForensicReports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        setLoading(true);
        const data = await listForensicReports();

        setReports(data.reports);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching reports:", error);
        setError(error.message || "Failed to fetch forensic reports");
        setLoading(false);
      }
    };

    fetchReports();
  }, []);

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
                Forensic Reports
              </h1>
              <p className="text-gray-400 text-lg poppins-light">
                Detailed security analysis reports with actionable insights
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

            {/* Reports List */}
            {!loading && reports.length === 0 && (
              <div className="text-center py-20 text-gray-400">
                <FiFileText className="text-6xl mx-auto mb-4 text-gray-500" />
                <h3 className="text-2xl font-semibold mb-2">
                  No Reports Found
                </h3>
                <p>Run a comprehensive analysis to generate forensic reports</p>
              </div>
            )}

            {!loading && reports.length > 0 && (
              <div className="grid grid-cols-1 gap-6">
                {reports.map((report) => (
                  <Link
                    to={`/reports/${report.report_id}`}
                    key={report.report_id}
                    className="block"
                  >
                    <div className="backdrop-blur-lg bg-white/2  rounded-2xl p-6 border border-[#7e4f31]/30 shadow-xl  hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 hover:scale-[1.01]">
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                        <div>
                          <div className="flex items-center gap-2 mb-2">
                            <FiFileText className="text-[#dd6317]" />
                            <h3 className="text-xl font-semibold text-white">
                              Report #{report.report_id.substring(0, 8)}
                            </h3>
                          </div>

                          <p className="text-gray-300 mb-4 line-clamp-2">
                            {report.executive_summary}
                          </p>

                          <div className="flex flex-wrap gap-3">
                            <div className="flex items-center gap-1 text-sm text-gray-400">
                              <FiClock className="text-[#dd6317]" />
                              <span>
                                {new Date(report.generated_at).toLocaleString()}
                              </span>
                            </div>

                            <div className="flex items-center gap-1 text-sm text-gray-400">
                              <FiAlertTriangle className="text-[#dd6317]" />
                              <span>{report.threat_count} threats</span>
                            </div>

                            {/* <div className="flex items-center gap-1 text-sm text-gray-400">
                              <FiServer className="text-[#dd6317]" />
                              <span>
                                {report.affected_systems_count} affected systems
                              </span>
                            </div> */}
                          </div>
                        </div>

                        <div className="flex items-center justify-end">
                          <div className="p-2 bg-[#dd6317]/20 text-[#dd6317] rounded-lg border border-[#dd6317]/30 hover:bg-[#dd6317]/30 transition-all duration-300">
                            <FiExternalLink size={20} />
                          </div>
                        </div>
                      </div>
                    </div>
                  </Link>
                ))}
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

export default ForensicReports;
