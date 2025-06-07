# 🔐 AI-Powered Cyber Forensic Tool

This is an AI-powered web application for analyzing server logs and detecting potential security threats. The system uses AI to identify common attack patterns (like SQL Injection, XSS, and Brute Force) and maps them to standard frameworks such as MITRE ATT&CK and OWASP Top 10.

## 🚀 Features

- **Dashboard** with system info, AI/API status, threat coverage
- **Basic Analysis** for fast log scanning (threats, severity, AI summary)
- **Comprehensive Analysis** with:
  - Executive summary
  - Threat type distribution (Pie chart)
  - Threats by IP (Bar chart)
  - IP enrichment (location, occurrences)
  - Security framework mapping (MITRE ATT&CK, OWASP Top 10)
  - Security recommendations
- **Forensic Reports** with detailed timelines and attack logs


## 📁 Project Structure

/frontend # React-based frontend
/backend # FastAPI backend
/data # Folder for geolocation database (create manually)


## ⚠️ Note About IP Geolocation Database

The file `IP2LOCATION-LITE-DB5.BIN` has been **excluded from this repository** due to its large size.

### To enable IP enrichment:
1. Go to the [IP2Location LITE download page](https://lite.ip2location.com/database-download)
2. Download the `.BIN` format of the **DB5 LITE** database
3. In your backend project root, create a folder named:
/data
4. Place the downloaded `IP2LOCATION-LITE-DB5.BIN` file inside the `/data` folder.


## 🔐 Environment Variables

In your backend root directory, create a `.env` file and add your **Groq API key**:

```env
GROQ_API_KEY=your_groq_api_key_here
```
You can get a Groq API key from https://console.groq.com


## 📦 Installation & Running

Make sure you have Python and Node.js installed.

Backend (Python FastAPI)

-cd backend
-python -m venv venv
-source venv/bin/activate  # or venv\Scripts\activate on Windows
-pip install -r requirements.txt
-python run.py

Frontend (React)

-cd frontend
-yarn
-yarn run dev
