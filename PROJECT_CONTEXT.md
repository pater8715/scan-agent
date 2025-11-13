# ScanAgent - Project Context & Scope

**Document Version:** 1.0  
**Last Updated:** November 13, 2025  
**Current Version:** 3.0.0  
**Maintainer:** pater8715  
**Repository:** https://github.com/pater8715/scan-agent

---

## 🎯 PROJECT OVERVIEW

### What is ScanAgent?

**ScanAgent** is an **intelligent, automated vulnerability scanning and analysis system** that combines multiple security tools (Nmap, Nikto, Gobuster, etc.) with AI-powered analysis to generate professional, actionable security reports.

### Mission Statement

> "Democratize professional security scanning by providing an intelligent, easy-to-use platform that transforms raw security tool outputs into actionable insights for both technical and non-technical users."

### Core Value Proposition

- ✅ **Automation:** One-click security scans without manual tool configuration
- ✅ **Intelligence:** AI-powered vulnerability analysis and prioritization
- ✅ **Clarity:** Transform cryptic tool outputs into clear, professional reports
- ✅ **Accessibility:** Web interface accessible to non-security experts
- ✅ **Actionability:** Specific recommendations for each finding

---

## 🏗️ PROJECT ARCHITECTURE

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER INTERFACE                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Web Dashboard (HTML/CSS/JS)                    │  │
│  │   - Scan submission form                         │  │
│  │   - Real-time progress tracking                  │  │
│  │   - Scan history listing                         │  │
│  │   - Report viewer                                │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    REST API LAYER                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │   FastAPI Backend (Python 3.12)                  │  │
│  │   - /api/scans/* - Scan management               │  │
│  │   - /api/reports/* - Report generation           │  │
│  │   - /api/storage/* - File management             │  │
│  │   - WebSocket for real-time updates              │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                  BUSINESS LOGIC LAYER                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │   ScanAgent Core (scanagent/)                    │  │
│  │   ├── agent.py - Main orchestrator               │  │
│  │   ├── nmap_scanner.py - Nmap integration         │  │
│  │   ├── nikto_scanner.py - Nikto integration       │  │
│  │   ├── gobuster.py - Directory enumeration        │  │
│  │   └── database.py - SQLite operations            │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Analysis & Intelligence (webapp/utils/)        │  │
│  │   ├── report_parser.py - Result parsing          │  │
│  │   ├── vulnerability_analyzer.py - Risk scoring   │  │
│  │   └── file_manager.py - File retention           │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                  DATA & STORAGE LAYER                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Database (SQLite)                              │  │
│  │   - scans table (scan metadata)                  │  │
│  │   - vulnerabilities table (findings)             │  │
│  │   - tools_output table (raw results)             │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │   File System                                    │  │
│  │   ├── storage/active/ - Recent scans (0-7 days)  │  │
│  │   ├── storage/archived/ - Old scans (8-30 days)  │  │
│  │   ├── storage/metadata/ - File tracking          │  │
│  │   └── reports/ - Generated reports               │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                  EXTERNAL TOOLS LAYER                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Security Tools (System installed)              │  │
│  │   ├── Nmap 7.94+ - Port/service scanning         │  │
│  │   ├── Nikto 2.5+ - Web vulnerability scanning    │  │
│  │   ├── Gobuster - Directory brute forcing         │  │
│  │   └── cURL - HTTP header analysis                │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Technology Stack

**Backend:**
- Python 3.12+
- FastAPI 0.104+ (REST API framework)
- Uvicorn (ASGI server)
- Pydantic (Data validation)
- SQLite3 (Database)

**Frontend:**
- HTML5, CSS3, JavaScript (Vanilla)
- Responsive design (mobile-friendly)
- No framework dependencies

**Security Tools:**
- Nmap 7.94+ (Network scanner)
- Nikto 2.5+ (Web scanner)
- Gobuster 3.6+ (Directory brute-force)
- cURL (HTTP client)

**Development:**
- Git (Version control)
- GitHub (Repository hosting)
- Virtual Environment (Python venv)

---

## 📋 PROJECT SCOPE

### IN SCOPE ✅

#### Core Functionality
1. **Automated Security Scanning**
   - Network port scanning (Nmap)
   - Web vulnerability scanning (Nikto)
   - Directory enumeration (Gobuster)
   - HTTP header analysis (cURL)
   - Multiple scan profiles (quick/standard/full/web-full)

2. **Intelligent Analysis**
   - Automated result parsing from raw outputs
   - Vulnerability classification (CRITICAL/HIGH/MEDIUM/LOW)
   - Risk scoring (0-100+ scale)
   - Known vulnerability detection (CVE matching)
   - Port/service risk assessment

3. **Professional Reporting**
   - Executive summary with risk level
   - HTML reports (responsive, printable)
   - JSON reports (structured data)
   - TXT reports (plain text)
   - Markdown reports (documentation-friendly)
   - Actionable recommendations

4. **Web Interface**
   - Scan submission form
   - Real-time progress tracking
   - Scan history listing
   - Report viewing/downloading
   - RESTful API

5. **Data Management**
   - SQLite database for persistence
   - File-based report storage
   - Scan metadata tracking
   - Basic file retention policies

6. **User Experience**
   - One-click scan initiation
   - Clear progress indicators
   - Intuitive web dashboard
   - No configuration required for basic use

#### Target Users
1. **Security Professionals**
   - Penetration testers
   - Security auditors
   - DevSecOps engineers

2. **System Administrators**
   - Network administrators
   - Web administrators
   - IT security teams

3. **Developers**
   - Full-stack developers
   - DevOps engineers
   - Security-conscious developers

4. **Security Students**
   - Cybersecurity learners
   - Bug bounty hunters
   - Security researchers

### OUT OF SCOPE ❌

#### Not Included (By Design)
1. **Active Exploitation**
   - No automated exploitation of vulnerabilities
   - No Metasploit integration
   - No brute-force password attacks
   - No DoS/DDoS capabilities

2. **Enterprise Features (v3.x)**
   - Multi-user authentication (planned v4.x)
   - Role-based access control (planned v4.x)
   - Team collaboration features (planned v4.x)
   - LDAP/SSO integration (planned v4.x)

3. **Advanced Integrations (v3.x)**
   - SIEM integration (planned v5.x)
   - Ticketing system integration (planned v5.x)
   - CI/CD pipeline native integration (planned v3.3)
   - Cloud provider APIs (planned v5.x)

4. **Compliance Features (v3.x)**
   - PCI-DSS compliance checking (planned v5.x)
   - HIPAA compliance validation (planned v5.x)
   - SOC2 reporting (planned v5.x)
   - Automated compliance reports (planned v5.x)

5. **Advanced Analytics**
   - Machine learning predictions (planned v4.x)
   - Threat intelligence feeds (planned v4.x)
   - Historical trend analysis (planned v4.x)
   - Attack surface mapping (planned v5.x)

#### Explicitly NOT Supported
- Windows-based scanning (Linux targets only)
- GUI desktop application (web-only)
- Mobile scanning apps
- Paid/commercial tool integrations
- Real-time monitoring/alerting
- Network traffic interception

---

## 🎯 CURRENT STATE (v3.0.0)

### What Works ✅

1. **Core Scanning Engine**
   - ✅ Nmap integration fully functional
   - ✅ Nikto integration working
   - ✅ Gobuster integration operational
   - ✅ HTTP header capture working
   - ✅ 4 scan profiles available
   - ✅ Background task execution

2. **Analysis & Intelligence**
   - ✅ ScanResultParser extracts structured data
   - ✅ VulnerabilityAnalyzer classifies findings
   - ✅ Risk scoring system (0-100+)
   - ✅ Port risk assessment (15 ports)
   - ✅ Vulnerable version detection (OpenSSH, Apache)
   - ✅ Severity classification working

3. **Reporting System**
   - ✅ Professional HTML reports with CSS
   - ✅ Structured JSON reports
   - ✅ Enhanced TXT reports with ASCII art
   - ✅ Markdown reports with emojis
   - ✅ Executive summary generation
   - ✅ Actionable recommendations

4. **Web Interface**
   - ✅ FastAPI backend operational
   - ✅ HTML dashboard functional
   - ✅ Real-time progress updates
   - ✅ Scan history display
   - ✅ Report download links
   - ✅ Mobile-responsive design

5. **Data Persistence**
   - ✅ SQLite database working
   - ✅ Scan metadata storage
   - ✅ File-based report storage
   - ✅ Metadata tracking system

### What's Partial ⚠️

1. **File Management**
   - ✅ Directory structure created
   - ✅ Basic metadata tracking
   - ⚠️ Automatic cleanup NOT implemented
   - ⚠️ Archiving system NOT complete
   - ⚠️ Retention policies NOT enforced

2. **Error Handling**
   - ✅ Basic error catching
   - ✅ Fallback to basic reports
   - ⚠️ User-friendly error messages limited
   - ⚠️ Detailed logging incomplete

3. **Testing**
   - ✅ Manual testing performed
   - ✅ Basic validation working
   - ⚠️ Unit tests NOT written
   - ⚠️ Integration tests NOT implemented
   - ⚠️ Test coverage: ~10%

### What Doesn't Work Yet ❌

1. **Deployment**
   - ❌ Docker containerization NOT done
   - ❌ Production deployment guide incomplete
   - ❌ Environment configuration limited
   - ❌ Secrets management NOT implemented

2. **Advanced Features**
   - ❌ Scheduled scans NOT available
   - ❌ Multi-target scanning NOT supported
   - ❌ Scan comparison NOT implemented
   - ❌ Email notifications NOT available

3. **Optimizations**
   - ❌ Caching layer NOT implemented
   - ❌ Database optimization NOT done
   - ❌ Parallel scanning NOT supported
   - ❌ Performance profiling NOT conducted

---

## 🔧 TECHNICAL DETAILS

### Directory Structure

```
scan-agent/
├── src/
│   └── scanagent/          # Core scanning engine
│       ├── agent.py        # Main orchestrator (500+ lines)
│       ├── nmap_scanner.py # Nmap integration
│       ├── nikto_scanner.py# Nikto integration
│       ├── gobuster.py     # Directory enumeration
│       └── database.py     # Database operations
│
├── webapp/                 # Web interface
│   ├── api/
│   │   └── scans.py        # Scan API endpoints (600+ lines)
│   ├── utils/
│   │   ├── report_parser.py      # Result parsing (450 lines)
│   │   └── file_manager.py       # File retention
│   ├── static/             # CSS, JS, images
│   └── templates/          # HTML templates
│
├── storage/                # File storage
│   ├── active/             # Recent scans (0-7 days)
│   ├── archived/           # Old scans (8-30 days)
│   └── metadata/           # File tracking JSON
│
├── reports/                # Generated reports
├── outputs/                # Raw scan outputs
├── docs/                   # Documentation
│   ├── changelog/
│   └── guides/
│
├── tests/                  # Test suite (mostly empty)
├── scripts/                # Utility scripts
├── requirements.txt        # Python dependencies
├── start-web.sh           # Web server launcher
└── README.md              # Main documentation
```

### Key Files & Responsibilities

| File | Lines | Purpose | Critical? |
|------|-------|---------|-----------|
| `src/scanagent/agent.py` | ~500 | Main scan orchestrator | ✅ Yes |
| `webapp/api/scans.py` | ~600 | REST API endpoints | ✅ Yes |
| `webapp/utils/report_parser.py` | ~450 | Intelligence layer | ✅ Yes |
| `src/scanagent/nmap_scanner.py` | ~200 | Nmap integration | ✅ Yes |
| `webapp/utils/file_manager.py` | ~150 | File retention | ⚠️ Partial |
| `src/scanagent/database.py` | ~300 | Database operations | ✅ Yes |

### Database Schema

```sql
-- scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- vulnerabilities table
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    type TEXT,
    severity TEXT,
    description TEXT,
    location TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- tools_output table
CREATE TABLE tools_output (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    tool_name TEXT,
    output_file TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

### API Endpoints

```
GET  /                      # Web dashboard
GET  /health               # Health check
POST /api/scans/start      # Start new scan
GET  /api/scans/status/{id}# Get scan status
GET  /api/scans/history    # List all scans
GET  /api/scans/report/{id}/{format} # Download report
```

### Scan Profiles

| Profile | Tools | Speed | Coverage | Use Case |
|---------|-------|-------|----------|----------|
| `quick` | Nmap (top 100 ports) | Fast (10s) | Low | Quick check |
| `standard` | Nmap (top 1000) + Nikto | Medium (2-5min) | Medium | Regular scan |
| `full` | Nmap (all) + Nikto + Gobuster | Slow (10-30min) | High | Deep scan |
| `web-full` | Nmap (web) + Nikto + Gobuster | Medium (5-10min) | Web-focused | Web apps |

---

## 🎓 LEARNING RESOURCES FOR NEW CONTRIBUTORS

### Understanding the Codebase

1. **Start Here:**
   - Read [`README.md`](README.md ) for overview
   - Review [`docs/GUIA_ESCANEO.md`](docs/GUIA_ESCANEO.md ) for usage
   - Check [`docs/changelog/CHANGELOG_v3.0.md`](docs/changelog/CHANGELOG_v3.0.md ) for recent changes

2. **Core Concepts:**
   - **Scan Flow:** User → API → ScanAgent → Tools → Parser → Analyzer → Reports
   - **Async Execution:** FastAPI BackgroundTasks for non-blocking scans
   - **Report Generation:** Raw outputs → Parsed data → Analyzed findings → Formatted reports

3. **Key Classes:**
   ```python
   # Main orchestrator
   ScanAgent(verbose=True, use_database=True)
   
   # Parsing layer
   ScanResultParser.parse_all_files(scan_dir, target)
   
   # Analysis layer
   VulnerabilityAnalyzer(scan_results).analyze()
   ```

### Prerequisites for Development

**Required Knowledge:**
- Python 3.10+ (intermediate level)
- FastAPI basics (async/await, routing)
- SQLite fundamentals
- Linux command line
- Basic security concepts

**Nice to Have:**
- Nmap command syntax
- HTTP protocol understanding
- Regex patterns
- Git workflow

### Development Setup

```bash
# 1. Clone repository
git clone https://github.com/pater8715/scan-agent.git
cd scan-agent

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install security tools (Ubuntu/Debian)
sudo apt update
sudo apt install nmap nikto gobuster

# 5. Run development server
./start-web.sh

# 6. Access web interface
open http://localhost:8000
```

### Testing Locally

```bash
# Quick test scan
curl -X POST http://localhost:8000/api/scans/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "profile": "quick",
    "output_formats": ["html", "json"],
    "save_to_db": true
  }'

# Check scan status
curl http://localhost:8000/api/scans/status/{scan_id}

# View reports
ls -lh reports/
```

---

## 🚨 IMPORTANT CONSTRAINTS & LIMITATIONS

### Technical Constraints

1. **Linux Only**
   - Must run on Linux (Ubuntu 20.04+ tested)
   - Windows not officially supported
   - macOS may work but untested

2. **Root/Sudo Required**
   - Nmap requires elevated privileges for SYN scans
   - Run with `sudo` or configure capabilities

3. **Network Access**
   - Outbound connectivity required for scans
   - Firewall must allow tool traffic
   - Some tools may be blocked by IDS/IPS

4. **Resource Requirements**
   - Minimum: 2GB RAM, 2 CPU cores
   - Recommended: 4GB RAM, 4 CPU cores
   - Disk: 10GB+ for scan outputs

### Legal & Ethical Constraints

1. **Authorization Required**
   - ⚠️ **ONLY scan authorized targets**
   - Get written permission before scanning
   - Unauthorized scanning is illegal

2. **Responsible Use**
   - Do not use for malicious purposes
   - Respect rate limits and bandwidth
   - Follow responsible disclosure

3. **Compliance**
   - Ensure compliance with local laws
   - Follow industry regulations (if applicable)
   - Respect privacy and data protection

### Design Constraints

1. **No Breaking Changes**
   - Maintain backward compatibility
   - Deprecate features gradually
   - Document all breaking changes

2. **Simplicity First**
   - Prefer simple solutions over complex
   - Avoid unnecessary dependencies
   - Keep configuration minimal

3. **Performance vs Features**
   - Don't sacrifice performance for features
   - Optimize critical paths
   - Profile before optimizing

---

## 📞 GETTING HELP

### Documentation

1. **Technical Docs:** [`docs/`](docs/ )
2. **API Reference:** [`docs/API.md`](docs/API.md ) (to be created)
3. **Changelog:** [`docs/changelog/CHANGELOG_v3.0.md`](docs/changelog/CHANGELOG_v3.0.md )
4. **Quick Reference:** [`QUICK_REFERENCE_v3.0.md`](QUICK_REFERENCE_v3.0.md )

### Support Channels

- **GitHub Issues:** https://github.com/pater8715/scan-agent/issues
- **Discussions:** https://github.com/pater8715/scan-agent/discussions
- **Email:** (To be added)

### Contributing

See [`ROADMAP.md`](ROADMAP.md ) for planned features and current priorities.

---

## 🎯 SUCCESS CRITERIA

### For v3.x (Current)
- ✅ Professional reports generated
- ✅ Web interface functional
- ✅ Core scanning working
- ⚠️ File management partial
- ❌ Docker not implemented

### For v4.x (Future)
- AI-powered analysis
- CVE database integration
- Enhanced vulnerability intelligence
- User authentication
- Multi-user support

### For v5.x (Long-term)
- Enterprise features
- Compliance reporting
- Cloud integrations
- Advanced analytics
- Mobile app

---

**Document Status:** 🟢 Complete  
**Next Review:** January 2026  
**Owner:** pater8715

---

*This document should be read by any AI agent or developer before making changes to the project. It provides the complete context needed to understand the project's goals, scope, and current state.*