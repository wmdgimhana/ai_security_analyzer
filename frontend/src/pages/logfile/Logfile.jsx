import React from "react";
import Sidebar from "../../components/sidebar/Sidebar";
import Analyzer from "./Analyzer";

const Logfile = () => {
  return (
    <div className="w-screen h-screen flex overflow-x-hidden overflow-y-hidden">
      <div className="flex-[1] w-full h-full bg-[#1e1f28]">
        <Sidebar />
      </div>
      <div className="flex-[6] w-full h-full bg-[#16171d] overflow-y-scroll">
        <Analyzer />
      </div>
    </div>
  );
};

export default Logfile;
