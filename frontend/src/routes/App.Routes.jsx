import React from "react";
import { Routes, Route } from "react-router-dom";
import Home from "../pages/home/Home";
import Logfile from "../pages/logfile/Logfile";
import ComprehensiveAnalysis from "../pages/comprehensive/ComprehensiveAnalysis";
import ForensicReports from "../pages/reports/ForensicReports";
import ReportDetail from "../pages/reports/ReportDetail";

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/analyze-file" element={<Logfile />} />
      <Route path="/comprehensive" element={<ComprehensiveAnalysis />} />
      <Route path="/reports" element={<ForensicReports />} />
      <Route path="/reports/:reportId" element={<ReportDetail />} />
    </Routes>
  );
}
