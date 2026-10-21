# Project Report — Enterprise Ransomware Assessment Tool

**Author:** Shivam Kore
**Language:** Python 3.8+
**Framework:** NIST Cybersecurity Framework (CSF) 2.0
**Version:** 1.0.0
**Submission:** IBM Project — Cybersecurity Risk Management

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Objectives](#2-project-objectives)
3. [System Architecture](#3-system-architecture)
4. [NIST CSF 2.0 Framework](#4-nist-csf-20-framework)
5. [Ransomware Threat Catalog](#5-ransomware-threat-catalog)
6. [Risk Scoring Methodology](#6-risk-scoring-methodology)
7. [Corporate Risk Register](#7-corporate-risk-register)
8. [Source Code Walkthrough](#8-source-code-walkthrough)
9. [System Workflow Diagram](#9-system-workflow-diagram)
10. [Conclusion & Recommendations](#10-conclusion--recommendations)

---

## 1. Executive Summary

This project delivers the **Enterprise Ransomware Assessment Tool** — a Python command-line application that enables organisations to build, maintain, and export a **Corporate Risk Register** focused on ransomware threats.

Every risk entry is mapped directly to the **NIST Cybersecurity Framework (CSF) 2.0**, the globally recognised cybersecurity governance standard. Risks are scored using a quantitative **Likelihood × Impact** matrix and linked to real-world ransomware threat families from a curated threat catalog.

### Key Statistics from the Demo Register

| Metric | Value |
|---|---|
| Total Risks | 10 |
| CRITICAL Risks (Score 20–25) | 3 |
| HIGH Risks (Score 12–19) | 7 |
| Average Risk Score | 17.0 / 25 |
| Most Impacted NIST Function | PROTECT (5 risks) |

---

## 2. Project Objectives

### Problem Statement
Ransomware has become the most financially damaging form of cybercrime globally. In 2023, over 4,500 organisations were claimed as ransomware victims on dark web leak sites. The average cost per incident exceeded **$5 million**. Despite this, many organisations lack a structured, framework-aligned approach to assessing their ransomware risk posture.

### Goals
- Provide a structured, automated corporate risk register for ransomware risks
- Map every risk to **NIST CSF 2.0** (function + category level)
- Quantify risk using a standard **Likelihood × Impact** model (score 1–25)
- Link risks to real ransomware families from a curated threat catalog
- Enable board-level reporting via CSV, JSON, and text export
- Require **zero external dependencies** — run entirely on Python standard library

### Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.8+ |
| Dependencies | None (stdlib: json, csv, os, sys, uuid, datetime, dataclasses, typing) |
| Data Storage | JSON files (no database required) |
| Security Framework | NIST CSF 2.0 |
| Threat Intelligence | CISA Advisories + MITRE ATT&CK |

---

## 3. System Architecture

The project is a single `main.py` file organised into 8 clearly labelled sections. It follows a clean layered design:

```
+------------------+     +------------------+     +------------------+
|  CONFIGURATION   |     |   DATA MODELS    |     |  THREAT CATALOG  |
|  NIST_CSF dict   |     |  RiskEntry       |     |  8 threats from  |
|  RISK_LEVELS     |     |  RansomwareThreat|     |  threats.json    |
|  Scoring scales  |     |  risk_score prop |     |  CISA / MITRE    |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         v                        v                        v
+------------------+     +------------------+     +------------------+
|  NIST HELPERS    |     |  RISK REGISTER   |     |  ASSESSMENT      |
|  validate_cat()  |     |  add/get/update  |     |  ENGINE          |
|  display_frame() |     |  delete/filter   |     |  Interactive     |
+------------------+     |  summary_stats() |     |  risk wizard     |
                          +--------+---------+     +------------------+
                                   |
                          +--------+---------+
                          |    REPORTER      |
                          |  print_register  |
                          |  print_summary   |
                          |  export_csv      |
                          |  export_json     |
                          |  export_text_rpt |
                          +--------+---------+
                                   |
                          +--------+---------+
                          |   CLI MENUS      |
                          |   main()         |
                          |   menu_view()    |
                          |   menu_manage()  |
                          |   menu_reports() |
                          +------------------+
```

### Data Flow
1. On startup, `RiskRegister` loads `data/risk_register.json` (auto-seeded with 10 demo risks on first run)
2. `ThreatCatalog` loads `data/threats.json` (auto-created from embedded data if missing)
3. The user navigates menus to view, add, update, delete, or export risks
4. All changes are persisted immediately to `data/risk_register.json`
5. Reports are exported to the `reports/` directory

---

## 4. NIST CSF 2.0 Framework

The NIST Cybersecurity Framework 2.0 organises cybersecurity activities into **6 Functions**:

```
+----------+    +----------+    +----------+    +----------+    +----------+    +----------+
|  GOVERN  | -> | IDENTIFY | -> | PROTECT  | -> |  DETECT  | -> | RESPOND  | -> | RECOVER  |
|   [GV]   |    |   [ID]   |    |   [PR]   |    |   [DE]   |    |   [RS]   |    |   [RC]   |
+----------+    +----------+    +----------+    +----------+    +----------+    +----------+
      ^_______________________________________________________________|
                    (Continuous improvement cycle)
```

| Code | Function | Description | Categories |
|---|---|---|---|
| GV | GOVERN | Risk management strategy and oversight | OC, RM, RR, PO, OV, SC |
| ID | IDENTIFY | Asset management and risk assessment | AM, RA, IM |
| PR | PROTECT | Safeguards and access controls | AA, AT, DS, PS, IR |
| DE | DETECT | Continuous monitoring and anomaly detection | CM, AE |
| RS | RESPOND | Incident response and communication | MA, AN, CO, MI |
| RC | RECOVER | Recovery planning and execution | RP, CO |

### Categories Used in This Project

| Category | Name | Function |
|---|---|---|
| PR.AT | Awareness and Training | PROTECT |
| PR.AA | Identity Management & Access Control | PROTECT |
| PR.DS | Data Security | PROTECT |
| PR.IR | Technology Infrastructure Resilience | PROTECT |
| ID.RA | Risk Assessment | IDENTIFY |
| RC.RP | Incident Recovery Plan Execution | RECOVER |
| RS.MA | Incident Management | RESPOND |
| GV.SC | Supply Chain Risk Management | GOVERN |
| DE.CM | Continuous Monitoring | DETECT |

---

## 5. Ransomware Threat Catalog

The tool includes 8 pre-seeded ransomware threat families drawn from CISA advisories and real-world attack data. Each threat includes MITRE ATT&CK technique mappings, target sectors, typical ransom amounts, and exfiltration behaviour.

| ID | Threat | Attack Vector | Typical Ransom | Double Extortion |
|---|---|---|---|---|
| TH-001 | LockBit 3.0 | Phishing, RDP | $50K – $50M | Yes |
| TH-002 | BlackCat (ALPHV) | Stolen Creds, VPN | $1M – $5M | Yes |
| TH-003 | Cl0p | Zero-Day (MOVEit) | $500K – $20M | Yes |
| TH-004 | Hive | Phishing, RDP | $100K – $6M | Yes |
| TH-005 | REvil (Sodinokibi) | Supply Chain | $5M – $70M | Yes |
| TH-006 | WannaCry | EternalBlue SMB | $300 – $600 | No |
| TH-007 | Royal Ransomware | Callback Phishing | $250K – $2M | Yes |
| TH-008 | Akira | Cisco VPN CVE | $200K – $4M | Yes |

### Threat Highlight: LockBit 3.0 (TH-001)
- **Encryption:** AES-256 (files) + RSA-2048 (key protection)
- **MITRE Techniques:** T1566 (Phishing), T1078 (Valid Accounts), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
- **Notable:** World's most prolific RaaS operation; leak site at lockbit3.onion; double extortion

### Threat Highlight: WannaCry (TH-006)
- **Encryption:** AES-128-CBC + RSA-2048
- **Vector:** NSA's EternalBlue exploit (MS17-010 in Windows SMB)
- **Notable:** Infected 200,000+ systems across 150 countries in 72 hours (2017); linked to North Korea's Lazarus Group; no data exfiltration

---

## 6. Risk Scoring Methodology

**Formula: Risk Score = Likelihood × Impact**

Both values are rated 1–5, producing a score between 1 and 25.

### Likelihood Scale

| Score | Label | Meaning |
|---|---|---|
| 1 | Rare | Event is unlikely in any foreseeable circumstances |
| 2 | Unlikely | Event could occur but is not expected |
| 3 | Possible | Event may occur at some point |
| 4 | Likely | Event is expected to occur in most circumstances |
| 5 | Almost Certain | Event is expected to occur in most or all circumstances |

### Impact Scale

| Score | Label | Meaning |
|---|---|---|
| 1 | Negligible | No meaningful disruption to operations |
| 2 | Minor | Minor disruption, resolved within hours |
| 3 | Moderate | Moderate disruption, resolved within days |
| 4 | Major | Serious disruption, significant financial/reputational damage |
| 5 | Catastrophic | Total loss of operations, regulatory action, existential threat |

### Risk Level Thresholds

| Level | Score Range | Response Required |
|---|---|---|
| **CRITICAL** | 20 – 25 | Immediate remediation. Executive escalation. Board notification. |
| **HIGH** | 12 – 19 | Urgent remediation within 30 days. CISO ownership. |
| **MEDIUM** | 6 – 11 | Remediation within 90 days. IT Security ownership. |
| **LOW** | 1 – 5 | Monitor and review annually. |

### Risk Matrix (5×5)

```
              Impact 1    Impact 2    Impact 3    Impact 4    Impact 5
Likelihood 5     5 LOW      10 MED     15 HIGH     20 CRIT     25 CRIT
Likelihood 4     4 LOW       8 MED     12 HIGH     16 HIGH     20 CRIT
Likelihood 3     3 LOW       6 MED      9 MED      12 HIGH     15 HIGH
Likelihood 2     2 LOW       4 LOW      6 MED       8 MED      10 MED
Likelihood 1     1 LOW       2 LOW      3 LOW       4 LOW       5 LOW
```

---

## 7. Corporate Risk Register

All 10 demo risks, sorted by score (highest first):

| Risk ID | Title | NIST | L | I | Score | Level | Status |
|---|---|---|---|---|---|---|---|
| 371B9A91 | Ransomware via Phishing Email | PR.AT | 5 | 5 | 25 | **CRITICAL** | Open |
| B929B7C9 | Exposed RDP Port Exploited | PR.AA | 4 | 5 | 20 | **CRITICAL** | Open |
| B9126207 | No Endpoint Detection & Response | DE.CM | 5 | 4 | 20 | **CRITICAL** | Open |
| B42189E5 | Unpatched VPN Appliance | ID.RA | 4 | 4 | 16 | HIGH | Open |
| EFFF220A | Lack of Ransomware IR Plan | RS.MA | 4 | 4 | 16 | HIGH | Open |
| D25A6691 | Insufficient Network Segmentation | PR.IR | 4 | 4 | 16 | HIGH | Open |
| 555A9B05 | No Offline Backup for Critical Servers | RC.RP | 3 | 5 | 15 | HIGH | Open |
| 7B152183 | Third-Party Vendor Privileged Access | GV.SC | 3 | 5 | 15 | HIGH | Open |
| A452EAE9 | Weak Password Policy / No MFA | PR.AA | 5 | 3 | 15 | HIGH | Mitigated |
| 03A95717 | Sensitive Data Stored Unencrypted | PR.DS | 3 | 4 | 12 | HIGH | Open |

> L = Likelihood (1–5) · I = Impact (1–5) · Score = L × I · Max = 25

### Risk Distribution by NIST Function

```
[PR] PROTECT    ████████████████████  5 risks
[DE] DETECT     ████                  1 risk
[ID] IDENTIFY   ████                  1 risk
[RS] RESPOND    ████                  1 risk
[RC] RECOVER    ████                  1 risk
[GV] GOVERN     ████                  1 risk
```

---

## 8. Source Code Walkthrough

The entire project is contained in a single `main.py` file (620+ lines), organised into 8 sections.

### Section 1 — Configuration
Defines all constants: `APP_NAME`, `APP_VERSION`, file paths, `RISK_LEVELS` thresholds, `LIKELIHOOD_SCALE`, `IMPACT_SCALE`, and the full `NIST_CSF` dictionary with all 6 functions and 22 categories.

### Section 2 — Data Models

**`RiskEntry` dataclass** — Represents one risk in the register:
```python
@dataclass
class RiskEntry:
    risk_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    title:      str = ""
    likelihood: int = 1   # 1-5
    impact:     int = 1   # 1-5
    status:     str = "Open"

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact   # Max = 25

    @property
    def risk_level(self) -> str:
        for level, (low, high) in RISK_LEVELS.items():
            if low <= self.risk_score <= high:
                return level
        return "UNKNOWN"
```

**`RansomwareThreat` dataclass** — Represents a threat family in the catalog with fields for attack vector, target sectors, MITRE techniques, ransom range, and exfiltration behaviour.

### Section 3 — Risk Register (CRUD)

```python
class RiskRegister:
    def add(self, entry: RiskEntry) -> RiskEntry      # Create
    def get(self, risk_id: str) -> Optional[RiskEntry] # Read
    def update(self, risk_id: str, **kwargs)           # Update
    def delete(self, risk_id: str) -> bool             # Delete
    def list_all(self) -> List[RiskEntry]
    def filter_by_level(self, level: str)
    def filter_by_status(self, status: str)
    def filter_by_nist_function(self, func_code: str)
    def filter_by_department(self, dept: str)
    def summary_stats(self) -> dict
```

All changes are persisted immediately to `data/risk_register.json`.

### Section 4 — Threat Catalog
Loads `data/threats.json` containing 8 ransomware threat families. Supports `list_all()`, `get(threat_id)`, and `display()`.

### Section 5 — Reporter
Handles all output:
- `print_register()` — formatted console table
- `print_entry()` — full detail view for a single risk
- `print_summary()` — statistics dashboard with bar chart
- `export_csv()` — CSV export to `reports/`
- `export_json()` — JSON export to `reports/`
- `export_text_report()` — full text report to `reports/`

### Section 6 — NIST CSF Helpers
- `display_framework()` — pretty-prints all 6 functions and 22 categories
- `validate_category(cat)` — returns True/False for any category code

### Section 7 — Assessment Engine
Interactive risk creation wizard that walks the user through all 17 fields of a `RiskEntry`, with guided NIST function/category selection and optional threat catalog linking.

### Section 8 — CLI Menus
Full menu-driven interface:
- Main menu with 6 options
- `menu_view()` — 6 view/filter modes
- `menu_manage()` — add, update, delete
- `menu_reports()` — 5 export options

---

## 9. System Workflow Diagram

```
User runs: python main.py
             |
             v
    +------------------+
    | First run?        |
    | Seed 10 demo      |
    | risks + threats   |
    +--------+---------+
             |
             v
    +------------------+
    |   MAIN MENU      |
    +------------------+
         |    |    |
    +----+    |    +----+
    |         |         |
    v         v         v
+--------+ +--------+ +--------+
| VIEW   | | MANAGE | | REPORT |
| Filter | | Add    | | CSV    |
| Search | | Update | | JSON   |
| Detail | | Delete | | TXT    |
+--------+ +--------+ +--------+
    |         |         |
    v         v         v
+----------------------------------+
|   data/risk_register.json        |
|   (persisted after every change) |
+----------------------------------+
```

---

## 10. Conclusion & Recommendations

### Project Conclusions

This tool demonstrates that a robust enterprise cybersecurity risk management application can be built entirely in Python with zero external dependencies. By grounding every risk in the NIST CSF 2.0 framework and linking risks to real-world threat intelligence, it provides immediate, actionable value.

The demo register reveals the most critical gaps in a typical enterprise's ransomware posture:

1. **No EDR** — Ransomware executes undetected (Score: 20/25 CRITICAL)
2. **Phishing** — #1 delivery vector with no advanced defence (Score: 25/25 CRITICAL)
3. **Exposed RDP** — Primary brute-force entry point (Score: 20/25 CRITICAL)

### Priority Recommendations

**Immediate (CRITICAL):**
- Deploy Endpoint Detection & Response (EDR) with ransomware rollback
- Implement AI-powered email sandboxing and Security Awareness Training
- Disable public-facing RDP; enforce VPN + MFA for all remote access

**Within 30 Days (HIGH):**
- Implement 3-2-1 backup strategy with immutable, air-gapped backups
- Develop and test a ransomware-specific Incident Response playbook
- Deploy network micro-segmentation to prevent lateral movement
- Establish Just-in-Time (JIT) privileged access for third-party vendors

### Future Enhancements
- Web-based dashboard with risk heat map (Flask/FastAPI)
- SIEM integration (Splunk, Microsoft Sentinel)
- Automated CVE feed for asset-based vulnerability tracking
- PDF report generation with charts
- Multi-user RBAC with database backend

---

*Report prepared by Shivam Kore — IBM Project, June 2025*
