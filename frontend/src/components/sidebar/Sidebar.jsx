import React from "react";
import { Link, useLocation } from "react-router-dom";
import { SiCyberdefenders } from "react-icons/si";
import {
  FiHome,
  FiFileText,
  FiMap,
  FiShield,
  FiBarChart2,
  FiFilePlus,
  FiGlobe,
} from "react-icons/fi";

const Sidebar = () => {
  const location = useLocation();

  const links = [
    {
      link: "/",
      name: "Dashboard",
      icon: <FiHome className="text-xl" />,
    },
    {
      link: "/analyze-file",
      name: "Basic Analyze",
      icon: <FiFileText className="text-xl" />,
    },
    {
      link: "/comprehensive",
      name: "Comprehensive Analysis",
      icon: <FiBarChart2 className="text-xl" />,
    },

    {
      link: "/reports",
      name: "Forensic Reports",
      icon: <FiFilePlus className="text-xl" />,
    },
  ];

  return (
    <div className="h-full w-full bg-[#1e1f28] flex flex-col items-center py-8 px-4 shadow-md">
      {/* Logo */}
      <div className="flex items-center gap-2 mb-14">
        <SiCyberdefenders className="text-[30px] text-[#dd6317]" />
        <div className="flex flex-col items-start">
          <span className="text-[20px] font-semibold text-white uppercase tracking-[2px]">
            CyberSage
          </span>
          <p className="text-[10px] poppins-light text-[#868bb4]">
            Powered by jackal
          </p>
        </div>
      </div>

      {/* Nav links */}
      <div className="flex flex-col w-full gap-3">
        {links.map((item, index) => (
          <Link
            key={index}
            to={item.link}
            className={`flex items-center gap-3 px-4 py-3 rounded-lg text-white transition-all duration-300
              ${
                location.pathname === item.link
                  ? "bg-gradient-to-r from-[#7e4f31] to-[#1e1f28]"
                  : "hover:bg-gradient-to-r hover:from-[#7e4f31] hover:to-[#1e1f28]"
              }`}
          >
            {item.icon}
            <span className="text-sm poppins-regular">{item.name}</span>
          </Link>
        ))}
      </div>
    </div>
  );
};

export default Sidebar;
