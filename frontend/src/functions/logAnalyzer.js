import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000, // 30 seconds timeout
  headers: {
    "Content-Type": "application/json",
  },
});

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const errorMessage =
      error.response?.data?.detail || error.message || "An error occurred";
    console.error("API Error:", errorMessage);
    throw new Error(errorMessage);
  }
);

/**
 * Analyze log content directly from text input
 * @param {string} logContent - The log content to analyze
 * @returns {Promise<Object>} Analysis response
 */
export const analyzeLogText = async (logContent) => {
  try {
    const response = await apiClient.post("/analyze/text", {
      log_content: logContent,
    });
    return response.data;
  } catch (error) {
    console.error("Error analyzing log text:", error);
    throw error;
  }
};

/**
 * Analyze uploaded log file
 * @param {File} file - The file to analyze
 * @returns {Promise<Object>} Analysis response
 */
export const analyzeLogFile = async (file) => {
  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await apiClient.post("/analyze/file", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
    return response.data;
  } catch (error) {
    console.error("Error analyzing log file:", error);
    throw error;
  }
};

/**
 * Upload file and get file information without analysis
 * @param {File} file - The file to upload
 * @returns {Promise<Object>} Upload response
 */
export const uploadFile = async (file) => {
  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await apiClient.post("/upload", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
    return response.data;
  } catch (error) {
    console.error("Error uploading file:", error);
    throw error;
  }
};

/**
 * Check API health status
 * @returns {Promise<Object>} Health check response
 */
export const checkHealth = async () => {
  try {
    const response = await apiClient.get("/health");
    return response.data;
  } catch (error) {
    console.error("Error checking health:", error);
    throw error;
  }
};

/**
 * Get API root information
 * @returns {Promise<Object>} Root response
 */
export const getApiInfo = async () => {
  try {
    const response = await apiClient.get("/api/info");
    return response.data;
  } catch (error) {
    console.error("Error getting API info:", error);
    throw error;
  }
};

/**
 * Extract and enrich IP addresses from log content
 * @param {string} logContent - The log content to analyze
 * @returns {Promise<Object>} IP enrichment response
 */
export const enrichIpsFromLogs = async (logContent) => {
  try {
    const response = await apiClient.post("/enrich/ips", {
      log_content: logContent,
    });
    return response.data;
  } catch (error) {
    console.error("Error enriching IPs:", error);
    throw error;
  }
};

/**
 * Map detected threats to security frameworks
 * @param {string} logContent - The log content to analyze
 * @returns {Promise<Object>} Framework mapping response
 */
export const mapToSecurityFrameworks = async (logContent) => {
  try {
    const response = await apiClient.post("/map/frameworks", {
      log_content: logContent,
    });
    return response.data;
  } catch (error) {
    console.error("Error mapping to frameworks:", error);
    throw error;
  }
};

/**
 * Generate data for visual dashboard
 * @param {string} logContent - The log content to analyze
 * @returns {Promise<Object>} Dashboard data response
 */
export const generateDashboardData = async (logContent) => {
  try {
    const response = await apiClient.post("/dashboard/data", {
      log_content: logContent,
    });
    return response.data;
  } catch (error) {
    console.error("Error generating dashboard data:", error);
    throw error;
  }
};

/**
 * Generate comprehensive forensic report
 * @param {string} logContent - The log content to analyze
 * @returns {Promise<Object>} Forensic report response
 */
export const generateForensicReport = async (logContent) => {
  try {
    const response = await apiClient.post("/report/generate", {
      log_content: logContent,
    });
    return response.data;
  } catch (error) {
    console.error("Error generating forensic report:", error);
    throw error;
  }
};

/**
 * Get a specific forensic report by ID
 * @param {string} reportId - The ID of the report to retrieve
 * @returns {Promise<Object>} Forensic report response
 */
export const getForensicReport = async (reportId) => {
  try {
    const response = await apiClient.get(`/report/${reportId}`);
    return response.data;
  } catch (error) {
    console.error("Error retrieving forensic report:", error);
    throw error;
  }
};

/**
 * List all available forensic reports
 * @returns {Promise<Object>} List of forensic reports
 */
export const listForensicReports = async () => {
  try {
    const response = await apiClient.get("/reports/list");
    return response.data;
  } catch (error) {
    console.error("Error listing forensic reports:", error);
    throw error;
  }
};

/**
 * Perform comprehensive analysis of uploaded log file
 * @param {File} file - The file to analyze
 * @returns {Promise<Object>} Comprehensive analysis response
 */
export const comprehensiveAnalysis = async (file) => {
  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await apiClient.post("/analyze/comprehensive", formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
    });
    return response.data;
  } catch (error) {
    console.error("Error performing comprehensive analysis:", error);
    throw error;
  }
};
