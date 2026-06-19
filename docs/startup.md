# 🚀 Security Investigator — Startup Guide

This document provides instructions on how to start and configure the Security Investigator platform locally.

## 📋 Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18 or higher
- **Azure CLI**: Installed and configured (`az login`)
- **Microsoft Sentinel**: Access to a Log Analytics workspace

---

## 🛠️ Step 1: Backend Setup
The backend is a FastAPI application that handles Sentinel queries, LLM orchestration, and threat intelligence enrichment.

1. **Navigate to the root directory**:
   ```powershell
   cd "Security Investigator - Frontend TEST"
   ```

2. **Install Python dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Ensure the `.env` file is populated with your credentials:
   - `SENTINEL_WORKSPACE_ID`: Your Log Analytics workspace ID
   - `AZURE_ANTHROPIC_API_KEY`: Your Azure AI Foundry key for Claude
   - `AZURE_ANTHROPIC_ENDPOINT`: Your Azure AI Foundry endpoint

4. **Start the Backend**:
   ```powershell
   python -m backend.main
   ```
   *The API will be available at `http://127.0.0.1:8000`.*

---

## 💻 Step 2: Frontend Setup
The frontend is a React application built with Vite and designed with PwC branding.

1. **Navigate to the frontend directory**:
   ```powershell
   cd frontend
   ```

2. **Install Node dependencies**:
   ```powershell
   npm install
   ```

3. **Start the Development Server**:
   ```powershell
   npm run dev
   ```
   *The UI will be available at `http://localhost:5173`.*

---

## 🔑 Step 3: Azure Authentication
The platform uses your local Azure CLI session by default. If the dashboard shows "Auth failed":

1. **Run the login command**:
   ```powershell
   az login --tenant a0502f78-df06-4cfc-a88b-1ee6fa628385
   ```
2. **Complete the login** in your web browser.
3. Refresh the Security Investigator dashboard.

---

## 🏗️ Architecture & Features
- **ARIA (Advanced Risk Intelligence Assistant)**: An agentic chat interface for natural language security investigations.
- **KQL Explorer**: Ad-hoc query execution against Sentinel data lake.
- **Threat Intel Enrichment**: Automated lookups via AbuseIPDB, IPInfo, and Shodan.
- **Automated Reporting**: Generation of professional HTML investigation reports.

---
*Created by Sentinel Engineering Team*
