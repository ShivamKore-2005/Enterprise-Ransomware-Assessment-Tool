# Enterprise Ransomware Assessment Tool

> **Corporate Risk Register mapped to the NIST Cybersecurity Framework (CSF) 2.0**
> Built with Python 3.8+ · Zero external dependencies · IBM Project

---

## About the Project

Ransomware is the most financially damaging form of cybercrime, costing organisations over **$30 billion annually**. This tool helps security teams build and manage a structured **Corporate Risk Register** focused entirely on ransomware threats.

Every risk entry is mapped directly to the **NIST CSF 2.0** framework — the globally recognised standard for managing cybersecurity risk — enabling gap analysis, board-level reporting, and audit-ready documentation.

---

## What the Tool Does

| Feature | Description |
|---|---|
| **Risk Register** | Add, view, update, delete, and filter ransomware risks |
| **NIST CSF 2.0 Mapping** | Every risk tagged to a function (GV/ID/PR/DE/RS/RC) and category |
| **Risk Scoring** | Likelihood × Impact matrix (1–5 scale, max score 25) |
| **Threat Catalog** | 8 real ransomware families with MITRE ATT&CK techniques |
| **Reports & Exports** | CSV, JSON, and text reports saved to the `reports/` folder |
| **Interactive CLI** | Full menu-driven interface — no coding knowledge needed to use |

---

## How to Run

```bash
# Step 1: Check Python version (needs 3.8+)
python --version

# Step 2: Run the tool
python main.py
```

> **No pip install needed.** The entire project runs on Python's built-in standard library.

On first launch, **10 demo risks** are automatically loaded so you can explore all features immediately.

---

## Files in This Repository

```
📁 Repository
├── main.py              ← Complete source code (single file, fully self-contained)
├── requirements.txt     ← Dependency list (Python stdlib only, no pip needed)
├── README.md            ← This file — project overview and usage guide
└── PROJECT_REPORT.md    ← Full technical report with diagrams, code, and analysis
```

---

## NIST CSF 2.0 Framework

The tool implements all **6 NIST CSF 2.0 Functions**:

```
[GV] GOVERN   → Risk management strategy, policies, oversight
[ID] IDENTIFY → Asset management, risk assessment
[PR] PROTECT  → Access control, data security, infrastructure resilience
[DE] DETECT   → Continuous monitoring, adverse event analysis
[RS] RESPOND  → Incident management, analysis, communication
[RC] RECOVER  → Recovery plan execution, recovery communication
```

---

## Risk Scoring Matrix

| | Impact 1 | Impact 2 | Impact 3 | Impact 4 | Impact 5 |
|---|---|---|---|---|---|
| **Likelihood 5** | 5 LOW | 10 MED | 15 HIGH | 20 **CRIT** | 25 **CRIT** |
| **Likelihood 4** | 4 LOW | 8 MED | 12 HIGH | 16 HIGH | 20 **CRIT** |
| **Likelihood 3** | 3 LOW | 6 MED | 9 MED | 12 HIGH | 15 HIGH |
| **Likelihood 2** | 2 LOW | 4 LOW | 6 MED | 8 MED | 10 MED |
| **Likelihood 1** | 1 LOW | 2 LOW | 3 LOW | 4 LOW | 5 LOW |

---

## Ransomware Threat Catalog

| ID | Threat | Attack Vector | Ransom (USD) | Double Extortion |
|---|---|---|---|---|
| TH-001 | LockBit 3.0 | Phishing, RDP | $50K – $50M | Yes |
| TH-002 | BlackCat (ALPHV) | Stolen Creds, VPN | $1M – $5M | Yes |
| TH-003 | Cl0p | Zero-Day MOVEit | $500K – $20M | Yes |
| TH-004 | Hive | Phishing, RDP | $100K – $6M | Yes |
| TH-005 | REvil | Supply Chain | $5M – $70M | Yes |
| TH-006 | WannaCry | EternalBlue SMB | $300 – $600 | No |
| TH-007 | Royal | Callback Phishing | $250K – $2M | Yes |
| TH-008 | Akira | Cisco VPN CVE | $200K – $4M | Yes |

---

## Demo Risk Register (Auto-loaded on First Run)

| Risk | NIST | Score | Level | Status |
|---|---|---|---|---|
| Ransomware via Phishing Email | PR.AT | 25/25 | **CRITICAL** | Open |
| Exposed RDP Port Exploited | PR.AA | 20/25 | **CRITICAL** | Open |
| No Endpoint Detection & Response | DE.CM | 20/25 | **CRITICAL** | Open |
| Unpatched VPN Appliance | ID.RA | 16/25 | HIGH | Open |
| Lack of Ransomware IR Plan | RS.MA | 16/25 | HIGH | Open |
| Insufficient Network Segmentation | PR.IR | 16/25 | HIGH | Open |
| No Offline Backup | RC.RP | 15/25 | HIGH | Open |
| Third-Party Vendor Privileged Access | GV.SC | 15/25 | HIGH | Open |
| Weak Password Policy / No MFA | PR.AA | 15/25 | HIGH | Mitigated |
| Sensitive Data Stored Unencrypted | PR.DS | 12/25 | HIGH | Open |

> **Summary: 10 risks · 3 CRITICAL · 7 HIGH · Average score 17.0/25**

---

## Project Structure (Code Architecture)

```
main.py is organised into 8 clearly labelled sections:

  [1] CONFIGURATION      — App constants, NIST CSF dictionary, scoring scales
  [2] DATA MODELS        — RiskEntry and RansomwareThreat dataclasses
  [3] RISK REGISTER      — CRUD operations + JSON persistence + filtering
  [4] THREAT CATALOG     — Load and display threat intelligence
  [5] REPORTER           — Console tables, CSV/JSON/TXT export
  [6] NIST CSF HELPERS   — Framework display and category validation
  [7] ASSESSMENT ENGINE  — Interactive risk creation wizard
  [8] CLI MENUS          — Main menu + sub-menus + entry point
```

---

## Technologies Used

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| Data Storage | JSON (no database needed) |
| Security Framework | NIST CSF 2.0 |
| Threat Intelligence | CISA Advisories + MITRE ATT&CK |
| External Dependencies | None (stdlib only) |

---

## Author

**Shivam Kore**
IBM Project — Cybersecurity Risk Management
GitHub: [@ShivamKore-2005](https://github.com/ShivamKore-2005)
