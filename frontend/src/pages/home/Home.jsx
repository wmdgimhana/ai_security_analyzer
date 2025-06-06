import React, { useState, useEffect } from "react";
import Sidebar from "../../components/sidebar/Sidebar";
import { FiBarChart2, FiGlobe, FiShield, FiAlertTriangle, FiClock } from "react-icons/fi";
import { SiCyberdefenders } from "react-icons/si";
import { checkHealth, getApiInfo } from "../../functions/logAnalyzer";

const Home = () => {
  const [apiInfo, setApiInfo] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [infoResponse, healthResponse] = await Promise.all([
          getApiInfo(),
          checkHealth()
        ]);
        setApiInfo(infoResponse);
        setHealthStatus(healthResponse);
      } catch (err) {
        setError(err.message || "Failed to fetch API information");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
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
                Security Dashboard
              </h1>
              <p className="text-gray-400 text-lg poppins-light">
                AI-powered security monitoring and analysis
              </p>
            </div>

            {loading ? (
              <div className="flex justify-center items-center h-64">
                <div className="relative">
                  <div className="w-16 h-16 border-4 border-[#dd6317]/30 border-t-[#dd6317] rounded-full animate-spin"></div>
                  <FiShield className="absolute inset-0 m-auto text-2xl text-[#dd6317] animate-pulse" />
                </div>
              </div>
            ) : error ? (
              <div className="bg-gradient-to-br from-red-900/20 via-red-800/20 to-red-900/20 rounded-2xl p-8 border border-red-500/30 shadow-2xl">
                <div className="flex items-center gap-3 mb-2">
                  <FiAlertTriangle className="text-2xl text-red-400" />
                  <h3 className="text-xl font-semibold text-red-400">
                    Connection Error
                  </h3>
                </div>
                <p className="text-red-300">{error}</p>
              </div>
            ) : (
              <>
                {/* Status Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                  <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-6 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 transform hover:scale-105">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="p-2 bg-gradient-to-r from-green-500/20 to-green-600/30 rounded-lg">
                        <FiShield className="text-xl text-green-400" />
                      </div>
                      <span className="text-gray-400 poppins-medium">API Status</span>
                    </div>
                    <div className="text-xl font-bold text-white poppins-bold flex items-center gap-2">
                      <span className="inline-block w-3 h-3 rounded-full bg-green-500 animate-pulse"></span>
                      {healthStatus?.status || "Unknown"}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      Last checked: {healthStatus ? new Date(healthStatus.timestamp).toLocaleString() : "N/A"}
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-6 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 transform hover:scale-105">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="p-2 bg-gradient-to-r from-blue-500/20 to-blue-600/30 rounded-lg">
                        <FiBarChart2 className="text-xl text-blue-400" />
                      </div>
                      <span className="text-gray-400 poppins-medium">AI Service</span>
                    </div>
                    <div className="text-xl font-bold text-white poppins-bold flex items-center gap-2">
                      <span className="inline-block w-3 h-3 rounded-full bg-blue-500 animate-pulse"></span>
                      {healthStatus?.ai_service || "Unknown"}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      Model: {apiInfo?.ai_model || "N/A"}
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-6 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 transform hover:scale-105">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="p-2 bg-gradient-to-r from-purple-500/20 to-purple-600/30 rounded-lg">
                        <SiCyberdefenders className="text-xl text-purple-400" />
                      </div>
                      <span className="text-gray-400 poppins-medium">Version</span>
                    </div>
                    <div className="text-xl font-bold text-white poppins-bold">
                      {apiInfo?.version || "Unknown"}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      Service: {apiInfo?.service || "N/A"}
                    </div>
                  </div>

                  <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-6 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 transform hover:scale-105">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="p-2 bg-gradient-to-r from-orange-500/20 to-orange-600/30 rounded-lg">
                        <FiClock className="text-xl text-orange-400" />
                      </div>
                      <span className="text-gray-400 poppins-medium">System Time</span>
                    </div>
                    <div className="text-xl font-bold text-white poppins-bold">
                      {new Date().toLocaleTimeString()}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      {new Date().toLocaleDateString()}
                    </div>
                  </div>
                </div>

                {/* Features Section */}
                <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500 mb-8">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg">
                      <FiShield className="text-xl text-white" />
                    </div>
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      Security Features
                    </h2>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {apiInfo?.analysis_features?.map((feature, index) => (
                      <div 
                        key={index}
                        className="bg-black/20 p-4 rounded-xl border border-white/10 transform transition-all duration-500 hover:scale-105"
                        style={{
                          animationDelay: `${index * 100}ms`,
                          animation: "fadeIn 0.8s ease-out forwards"
                        }}
                      >
                        <div className="text-gray-300 poppins-medium">{feature}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Threat Detection Section */}
                <div className="bg-gradient-to-br from-[#1e1f28] via-[#232530] to-[#1a1b26] rounded-2xl p-8 border border-[#7e4f31]/30 shadow-2xl backdrop-blur-sm hover:shadow-[#dd6317]/10 hover:shadow-2xl transition-all duration-500">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="p-2 bg-gradient-to-r from-[#dd6317] to-orange-500 rounded-lg">
                      <FiAlertTriangle className="text-xl text-white" />
                    </div>
                    <h2 className="text-2xl font-bold bg-gradient-to-r from-[#dd6317] to-orange-400 bg-clip-text text-transparent poppins-bold">
                      Supported Threat Types
                    </h2>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {apiInfo?.threat_detection?.supported_threats?.map((threat, index) => (
                      <div 
                        key={index}
                        className="bg-gradient-to-br from-red-500/10 to-red-600/20 p-3 rounded-xl border border-red-500/30 transform transition-all duration-300 hover:scale-105"
                        style={{
                          animationDelay: `${index * 100}ms`,
                          animation: "slideInLeft 0.6s ease-out forwards"
                        }}
                      >
                        <div className="text-gray-300 poppins-medium text-sm">{threat}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
