# 🛡️ Blue Team Co-Pilot — AI-Powered SOC Operations Platform

An intelligent Security Operations Center (SOC) assistant that leverages **multi-agent AI architecture** and **real-time SIEM data** to automate threat detection, attack path analysis, and incident response. Built as a portfolio project demonstrating advanced AI/ML integration in cybersecurity operations.

---

## ✨ Key Features

### 🤖 AI-Powered Modules
| Module | Description |
|---|---|
| **Signal Fusion Agent** | Correlates events from multiple sources using union-find algorithm and enriches them with threat intelligence |
| **Attack-Path Agent** | Maps incidents to MITRE ATT&CK kill chain, builds directed attack graphs, and calculates completeness scores |
| **Response Orchestrator** | Generates prioritized containment/remediation actions with AI trust scores |
| **AI Threat Hunter** | Natural language threat hunting across all incident data, powered by Groq AI |
| **AI Report Generator** | One-click executive security reports with AI-written analysis |
| **Context-Aware Chatbot** | SOC assistant that knows your actual incidents and can reference them by ID |
| **AI Dashboard Insights** | Real-time AI risk assessment, predictions, and quick-win recommendations |
| **AI Incident Analysis** | Attack narratives, risk assessment, and predicted attacker next moves |

### 📊 Real-Time Dataset
Ingests **100,000+ real SIEM events** from the [Hugging Face Advanced SIEM Dataset](https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset) including:
- Firewall logs, IDS alerts, authentication events
- Endpoint activities, network traffic, cloud operations
- IoT device events, AI system interactions
- MITRE ATT&CK technique mapping
- Behavioral analytics and anomaly indicators

### 🎨 Premium UI/UX
- Dark & Light mode with smooth transitions
- Glassmorphism design with animated backgrounds
- Interactive attack graph visualization
- Real-time WebSocket alerts
- Responsive layout with micro-animations

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │Dashboard │ │ Incidents│ │  Threat  │ │ Reports  │            │
│  │+AI Insight│ │+AI Analys│ │  Hunter  │ │Generator │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │  Alerts  │ │  Attack  │ │ Response │ │ AI Chat  │            │
│  │  Table   │ │  Graph   │ │ Actions  │ │   Bot    │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
└────────────────────────┬───────────────────────────────────────────┘
                         │ REST API + WebSocket
┌────────────────────────┴───────────────────────────────────────────┐
│                    Backend (FastAPI + Motor)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐         │
│  │ Detection   │  │ Attack Path  │  │ Response        │         │
│  │ Pipeline    │  │ Agent        │  │ Orchestrator    │         │
│  └─────────────┘  └──────────────┘  └─────────────────┘         │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐         │
│  │ AI Engine   │  │ Dataset      │  │ Context-Aware   │         │
│  │ (Groq API)  │  │ Loader (HF)  │  │ Chatbot         │         │
│  └─────────────┘  └──────────────┘  └─────────────────┘         │
└────────────────────────┬───────────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │        MongoDB                │
         │  incidents · alerts · actions │
         │  attack_graphs · system_data  │
         └───────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React, Vite, Recharts, Lucide Icons |
| **Backend** | Python, FastAPI, Motor (async MongoDB) |
| **Database** | MongoDB |
| **AI/ML** | Groq API (Llama 3.1), Custom Detection Pipeline |
| **Dataset** | Hugging Face Advanced SIEM Dataset (100K records) |
| **Auth** | JWT + bcrypt |
| **Real-time** | WebSocket |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- MongoDB (local or Atlas)

### Backend Setup
```bash
cd backend
python -m venv venv
venv\Scripts\activate    # Windows
# source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python -m uvicorn app:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Environment Variables (Optional)
```env
MONGO_URI=mongodb://localhost:27017
GROQ_API_KEY=your_groq_api_key
JWT_SECRET=your_jwt_secret
```

### Default Login
- **Username:** admin
- **Password:** admin123

---

## 📁 Project Structure

```
blue_team_copilot/
├── backend/
│   ├── app.py              # FastAPI server + all REST/WebSocket endpoints
│   ├── detection.py         # Signal Fusion Agent (event correlation)
│   ├── attack_path.py       # Attack-Path Agent (MITRE ATT&CK mapping)
│   ├── response.py          # Response Orchestrator (action generation)
│   ├── ai_engine.py         # Central AI service (Groq API integration)
│   ├── chatbot.py           # Context-aware AI chatbot
│   ├── dataset_loader.py    # Real-time dataset fetcher (Hugging Face)
│   ├── auth.py              # JWT authentication
│   ├── threats.py           # Manual threat registration
│   ├── logs.json            # Fallback local log data
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx     # Main dashboard + AI insights
│   │   │   ├── Alerts.jsx        # Alert table with filtering
│   │   │   ├── Incidents.jsx     # Incident list + AI analysis
│   │   │   ├── AttackGraph.jsx   # Interactive attack visualization
│   │   │   ├── Actions.jsx       # Response action management
│   │   │   ├── ThreatHunter.jsx  # AI threat hunting page
│   │   │   ├── Reports.jsx       # AI executive report generator
│   │   │   ├── Login.jsx         # Authentication page
│   │   │   └── RegisterThreat.jsx # Manual threat entry
│   │   ├── components/
│   │   │   ├── Sidebar.jsx       # Navigation sidebar
│   │   │   ├── Chatbot.jsx       # AI chat interface
│   │   │   ├── AnimatedBackground.jsx
│   │   │   └── ThreatGauge.jsx
│   │   ├── hooks/useApi.js       # API client functions
│   │   ├── App.jsx               # Router + layout
│   │   └── index.css             # Full design system
│   └── package.json
└── README.md
```

---

## 🔑 What Makes This Unique

1. **Multi-Agent AI Architecture** — Not just one AI model, but a coordinated system of specialized agents
2. **Real-Time SIEM Data** — Fetches from Hugging Face's 100K-record Advanced SIEM Dataset
3. **Natural Language Threat Hunting** — Query incidents in plain English  
4. **AI Attack Progression** — Predicts which MITRE ATT&CK phases come next
5. **Context-Aware AI Chat** — The chatbot actually knows your incidents by ID
6. **Trust Scores on Everything** — AI recommendations include confidence levels
7. **Refresh from Real Data** — One-click dataset refresh from live API
8. **Professional Report Generation** — Board-ready reports from one click

---

## 📜 Dataset Citation

```bibtex
@dataset{advanced_siem_dataset_2025,
  author = {sunnythakur},
  title = {Advanced SIEM Dataset for Cybersecurity ML},
  year = {2025},
  publisher = {Hugging Face},
  url = {https://huggingface.co/datasets/darkknight25/advanced_siem_dataset}
}
```

---

## 📄 License

MIT License

---

*Built with ❤️ for cybersecurity by an aspiring Blue Teamer*
