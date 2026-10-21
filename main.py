# -*- coding: utf-8 -*-
"""
=============================================================================
  ENTERPRISE RANSOMWARE ASSESSMENT TOOL
  Corporate Risk Register mapped to NIST Cybersecurity Framework (CSF) 2.0
  Author  : Shivam Kore
  Version : 1.0.0
  Language: Python 3.8+ (Standard Library only - no pip install needed)
=============================================================================
"""

import os
import sys
import json
import csv
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import List, Optional

# Ensure UTF-8 output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass

# =============================================================================
#  CONFIGURATION
# =============================================================================

APP_NAME    = "Enterprise Ransomware Assessment Tool"
APP_VERSION = "1.0.0"
REPORTS_DIR = "reports"
DATA_DIR    = "data"
REGISTER_FILE = os.path.join(DATA_DIR, "risk_register.json")
THREATS_FILE  = os.path.join(DATA_DIR, "threats.json")

RISK_LEVELS = {
    "CRITICAL": (20, 25),
    "HIGH":     (12, 19),
    "MEDIUM":   (6,  11),
    "LOW":      (1,   5),
}

LIKELIHOOD_SCALE = {
    1: "Rare",
    2: "Unlikely",
    3: "Possible",
    4: "Likely",
    5: "Almost Certain",
}

IMPACT_SCALE = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Catastrophic",
}

# NIST CSF 2.0 - All 6 Functions and their Categories
NIST_CSF = {
    "GV": {
        "name": "GOVERN",
        "description": "Establishes cybersecurity risk management strategy, policies and oversight.",
        "categories": {
            "GV.OC": "Organizational Context",
            "GV.RM": "Risk Management Strategy",
            "GV.RR": "Roles, Responsibilities & Authorities",
            "GV.PO": "Policy",
            "GV.OV": "Oversight",
            "GV.SC": "Cybersecurity Supply Chain Risk Management",
        },
    },
    "ID": {
        "name": "IDENTIFY",
        "description": "Understand organisational assets, suppliers, and related cybersecurity risks.",
        "categories": {
            "ID.AM": "Asset Management",
            "ID.RA": "Risk Assessment",
            "ID.IM": "Improvement",
        },
    },
    "PR": {
        "name": "PROTECT",
        "description": "Implement safeguards to manage and limit cybersecurity risks.",
        "categories": {
            "PR.AA": "Identity Management, Authentication & Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.PS": "Platform Security",
            "PR.IR": "Technology Infrastructure Resilience",
        },
    },
    "DE": {
        "name": "DETECT",
        "description": "Find and analyse possible cybersecurity attacks and compromises.",
        "categories": {
            "DE.CM": "Continuous Monitoring",
            "DE.AE": "Adverse Event Analysis",
        },
    },
    "RS": {
        "name": "RESPOND",
        "description": "Take action regarding a detected cybersecurity incident.",
        "categories": {
            "RS.MA": "Incident Management",
            "RS.AN": "Incident Analysis",
            "RS.CO": "Incident Response Reporting & Communication",
            "RS.MI": "Incident Mitigation",
        },
    },
    "RC": {
        "name": "RECOVER",
        "description": "Restore assets and operations after a cybersecurity incident.",
        "categories": {
            "RC.RP": "Incident Recovery Plan Execution",
            "RC.CO": "Incident Recovery Communication",
        },
    },
}

# =============================================================================
#  DATA MODELS
# =============================================================================

@dataclass
class RiskEntry:
    """Represents one risk in the Corporate Risk Register."""

    risk_id:               str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    title:                 str = ""
    description:           str = ""
    nist_function:         str = ""      # e.g. "PR"
    nist_category:         str = ""      # e.g. "PR.DS"
    threat_id:             Optional[str] = None
    threat_name:           str = ""
    likelihood:            int = 1       # 1-5
    impact:                int = 1       # 1-5
    existing_controls:     str = ""
    recommended_controls:  str = ""
    asset_affected:        str = ""
    risk_owner:            str = ""
    department:            str = ""
    date_identified:       str = field(default_factory=lambda: date.today().isoformat())
    review_date:           str = ""
    status:                str = "Open"  # Open | Mitigated | Accepted | Transferred | Closed

    @property
    def risk_score(self) -> int:
        """Calculated as Likelihood x Impact (max 25)."""
        return self.likelihood * self.impact

    @property
    def risk_level(self) -> str:
        """Maps risk score to CRITICAL / HIGH / MEDIUM / LOW."""
        score = self.risk_score
        for level, (low, high) in RISK_LEVELS.items():
            if low <= score <= high:
                return level
        return "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "risk_id": self.risk_id, "title": self.title,
            "description": self.description, "nist_function": self.nist_function,
            "nist_category": self.nist_category, "threat_id": self.threat_id,
            "threat_name": self.threat_name, "likelihood": self.likelihood,
            "impact": self.impact, "risk_score": self.risk_score,
            "risk_level": self.risk_level, "existing_controls": self.existing_controls,
            "recommended_controls": self.recommended_controls,
            "asset_affected": self.asset_affected, "risk_owner": self.risk_owner,
            "department": self.department, "date_identified": self.date_identified,
            "review_date": self.review_date, "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RiskEntry":
        entry = cls()
        for key, value in data.items():
            if key not in ("risk_score", "risk_level") and hasattr(entry, key):
                setattr(entry, key, value)
        return entry


@dataclass
class RansomwareThreat:
    """Represents a ransomware threat family in the Threat Catalog."""

    threat_id:            str = ""
    name:                 str = ""
    family:               str = ""
    description:          str = ""
    attack_vector:        str = ""
    target_sectors:       List[str] = field(default_factory=list)
    nist_functions_impacted: List[str] = field(default_factory=list)
    typical_ransom_usd:   str = ""
    encryption_method:    str = ""
    data_exfiltration:    bool = False
    double_extortion:     bool = False
    mitre_techniques:     List[str] = field(default_factory=list)
    iocs:                 List[str] = field(default_factory=list)
    references:           List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "RansomwareThreat":
        t = cls()
        for key, value in data.items():
            if hasattr(t, key):
                setattr(t, key, value)
        return t


# =============================================================================
#  RISK REGISTER  (CRUD + Persistence)
# =============================================================================

class RiskRegister:
    """In-memory Corporate Risk Register backed by a JSON file."""

    def __init__(self, filepath: str = REGISTER_FILE):
        self.filepath = filepath
        self._entries: List[RiskEntry] = []
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as fh:
                    self._entries = [RiskEntry.from_dict(r) for r in json.load(fh)]
            except (json.JSONDecodeError, KeyError):
                self._entries = []

    def save(self) -> None:
        dir_part = os.path.dirname(self.filepath)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        with open(self.filepath, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in self._entries], fh, indent=2)

    def add(self, entry: RiskEntry) -> RiskEntry:
        self._entries.append(entry)
        self.save()
        return entry

    def get(self, risk_id: str) -> Optional[RiskEntry]:
        for e in self._entries:
            if e.risk_id.upper() == risk_id.upper():
                return e
        return None

    def update(self, risk_id: str, **kwargs) -> Optional[RiskEntry]:
        entry = self.get(risk_id)
        if entry is None:
            return None
        for key, value in kwargs.items():
            if hasattr(entry, key) and key not in ("risk_id", "risk_score", "risk_level"):
                setattr(entry, key, value)
        self.save()
        return entry

    def delete(self, risk_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.risk_id.upper() != risk_id.upper()]
        if len(self._entries) < before:
            self.save()
            return True
        return False

    def list_all(self) -> List[RiskEntry]:
        return list(self._entries)

    def filter_by_level(self, level: str) -> List[RiskEntry]:
        return [e for e in self._entries if e.risk_level == level.upper()]

    def filter_by_status(self, status: str) -> List[RiskEntry]:
        return [e for e in self._entries if e.status.lower() == status.lower()]

    def filter_by_nist_function(self, func_code: str) -> List[RiskEntry]:
        return [e for e in self._entries if e.nist_function.upper() == func_code.upper()]

    def filter_by_department(self, dept: str) -> List[RiskEntry]:
        return [e for e in self._entries if e.department.lower() == dept.lower()]

    def summary_stats(self) -> dict:
        total = len(self._entries)
        by_level  = {level: 0 for level in RISK_LEVELS}
        by_status, by_nist = {}, {}
        for e in self._entries:
            by_level[e.risk_level]   = by_level.get(e.risk_level, 0) + 1
            by_status[e.status]      = by_status.get(e.status, 0) + 1
            by_nist[e.nist_function] = by_nist.get(e.nist_function, 0) + 1
        avg = sum(e.risk_score for e in self._entries) / total if total else 0
        return {
            "total_risks": total, "by_level": by_level,
            "by_status": by_status, "by_nist_function": by_nist,
            "average_risk_score": round(avg, 2),
        }


# =============================================================================
#  THREAT CATALOG
# =============================================================================

class ThreatCatalog:
    """Ransomware threat catalog loaded from threats.json."""

    def __init__(self, filepath: str = THREATS_FILE):
        self._threats: List[RansomwareThreat] = []
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as fh:
                self._threats = [RansomwareThreat.from_dict(t) for t in json.load(fh)]

    def list_all(self) -> List[RansomwareThreat]:
        return list(self._threats)

    def get(self, threat_id: str) -> Optional[RansomwareThreat]:
        for t in self._threats:
            if t.threat_id.upper() == threat_id.upper():
                return t
        return None

    def display(self) -> None:
        print("\n" + "=" * 70)
        print("  RANSOMWARE THREAT CATALOG")
        print("=" * 70)
        for t in self._threats:
            print(f"\n  [{t.threat_id}] {t.name}  ({t.family})")
            print(f"       Vector  : {t.attack_vector}")
            print(f"       Sectors : {', '.join(t.target_sectors)}")
            print(f"       Ransom  : {t.typical_ransom_usd}")
            print(f"       Exfil   : {'Yes' if t.data_exfiltration else 'No'}"
                  f"   Double Extortion: {'Yes' if t.double_extortion else 'No'}")
            print(f"       MITRE   : {', '.join(t.mitre_techniques)}")
        print("=" * 70 + "\n")


# =============================================================================
#  REPORTER  (Console output + CSV / JSON / TXT export)
# =============================================================================

class Reporter:
    """Console display and file export for the risk register."""

    @staticmethod
    def print_register(entries: List[RiskEntry], title: str = "RISK REGISTER") -> None:
        if not entries:
            print("  (no entries to display)\n")
            return
        print(f"\n{'=' * 90}")
        print(f"  {title}")
        print(f"{'=' * 90}")
        print(f"{'ID':<10} {'Title':<32} {'NIST':<8} {'L':>2} {'I':>2} {'Score':>5}  {'Level':<10} {'Status'}")
        print("-" * 90)
        for e in entries:
            print(f"{e.risk_id:<10} {e.title[:31]:<32} {e.nist_category:<8} "
                  f"{e.likelihood:>2} {e.impact:>2} {e.risk_score:>5}  "
                  f"{e.risk_level:<10} {e.status}")
        print("=" * 90 + "\n")

    @staticmethod
    def print_entry(entry: RiskEntry) -> None:
        print(f"\n{'-' * 60}")
        print(f"  RISK DETAIL  -  {entry.risk_id}")
        print("-" * 60)
        fields = [
            ("Title",                entry.title),
            ("Description",          entry.description),
            ("NIST Function",        f"{entry.nist_function} - {NIST_CSF.get(entry.nist_function, {}).get('name', '')}"),
            ("NIST Category",        entry.nist_category),
            ("Threat",               f"{entry.threat_id or 'N/A'}  {entry.threat_name}"),
            ("Asset Affected",       entry.asset_affected),
            ("Department",           entry.department),
            ("Risk Owner",           entry.risk_owner),
            ("Likelihood",           f"{entry.likelihood}/5"),
            ("Impact",               f"{entry.impact}/5"),
            ("Risk Score",           f"{entry.risk_score}/25"),
            ("Risk Level",           entry.risk_level),
            ("Existing Controls",    entry.existing_controls),
            ("Recommended Controls", entry.recommended_controls),
            ("Date Identified",      entry.date_identified),
            ("Review Date",          entry.review_date),
            ("Status",               entry.status),
        ]
        for label, value in fields:
            print(f"  {label:<24}: {value}")
        print("-" * 60 + "\n")

    @staticmethod
    def print_summary(stats: dict) -> None:
        print(f"\n{'=' * 60}")
        print("  RISK REGISTER - SUMMARY DASHBOARD")
        print("=" * 60)
        print(f"  Total Risks    : {stats['total_risks']}")
        print(f"  Avg Risk Score : {stats['average_risk_score']}/25")
        print("\n  By Risk Level:")
        for level, count in stats["by_level"].items():
            bar = "#" * count
            print(f"    {level:<10}  {count:>3}  {bar}")
        print("\n  By Status:")
        for status, count in stats["by_status"].items():
            print(f"    {status:<16}  {count}")
        print("\n  By NIST Function:")
        for func, count in stats["by_nist_function"].items():
            func_name = NIST_CSF.get(func, {}).get("name", func)
            print(f"    [{func}] {func_name:<22}  {count}")
        print("=" * 60 + "\n")

    @staticmethod
    def export_csv(entries: List[RiskEntry], filename: str = "") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if not filename:
            filename = os.path.join(REPORTS_DIR, f"risk_register_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not entries:
            print("  [!] No entries to export.")
            return ""
        with open(filename, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(entries[0].to_dict().keys()))
            writer.writeheader()
            for e in entries:
                writer.writerow(e.to_dict())
        print(f"  [OK] CSV exported -> {filename}")
        return filename

    @staticmethod
    def export_json(entries: List[RiskEntry], filename: str = "") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if not filename:
            filename = os.path.join(REPORTS_DIR, f"risk_register_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in entries], fh, indent=2)
        print(f"  [OK] JSON exported -> {filename}")
        return filename

    @staticmethod
    def export_text_report(entries: List[RiskEntry], stats: dict, filename: str = "") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if not filename:
            filename = os.path.join(REPORTS_DIR, f"risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        lines = [
            "=" * 70,
            "  ENTERPRISE RANSOMWARE RISK ASSESSMENT REPORT",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            f"\n  Total Risks    : {stats['total_risks']}",
            f"  Avg Risk Score : {stats['average_risk_score']}/25\n",
            "  Risk Level Breakdown:",
        ]
        for level, count in stats["by_level"].items():
            lines.append(f"    {level:<12}: {count}")
        lines.append("\n  NIST Function Breakdown:")
        for func, count in stats["by_nist_function"].items():
            lines.append(f"    [{func}] {NIST_CSF.get(func, {}).get('name', func):<20}: {count}")
        lines += ["\n" + "=" * 70, "  RISK ENTRIES (sorted by score, highest first)", "=" * 70]
        for e in sorted(entries, key=lambda x: x.risk_score, reverse=True):
            lines += [
                f"\n  [{e.risk_id}] {e.title}",
                f"  Level: {e.risk_level}  Score: {e.risk_score}/25  Status: {e.status}",
                f"  NIST: {e.nist_category}  Threat: {e.threat_name or 'N/A'}",
                f"  Asset: {e.asset_affected}  Owner: {e.risk_owner}",
                f"  Description: {e.description}",
                f"  Existing Controls: {e.existing_controls}",
                f"  Recommended Controls: {e.recommended_controls}",
                "  " + "-" * 60,
            ]
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"  [OK] Text report exported -> {filename}")
        return filename


# =============================================================================
#  NIST CSF HELPERS
# =============================================================================

def display_framework() -> None:
    print("\n" + "=" * 70)
    print("  NIST CYBERSECURITY FRAMEWORK (CSF) 2.0 - OVERVIEW")
    print("=" * 70)
    for code, func in NIST_CSF.items():
        print(f"\n  [{code}] {func['name']}")
        print(f"       {func['description']}")
        print(f"       Categories:")
        for cat_code, cat_name in func["categories"].items():
            print(f"         * {cat_code}  -  {cat_name}")
    print("=" * 70 + "\n")


def validate_category(cat: str) -> bool:
    func_code = cat.split(".")[0].upper()
    return cat.upper() in NIST_CSF.get(func_code, {}).get("categories", {})


# =============================================================================
#  INTERACTIVE ASSESSMENT ENGINE
# =============================================================================

class AssessmentEngine:
    """Guides the user through creating a new risk entry interactively."""

    def __init__(self):
        self.catalog = ThreatCatalog()

    @staticmethod
    def _prompt(label: str, default: str = "") -> str:
        hint = f" [{default}]" if default else ""
        val = input(f"  {label}{hint}: ").strip()
        return val if val else default

    @staticmethod
    def _prompt_int(label: str, min_val: int, max_val: int, default: int = 1) -> int:
        while True:
            raw = input(f"  {label} ({min_val}-{max_val}) [{default}]: ").strip()
            if not raw:
                return default
            if raw.isdigit() and min_val <= int(raw) <= max_val:
                return int(raw)
            print(f"    [!] Enter a number between {min_val} and {max_val}.")

    @staticmethod
    def _prompt_choice(label: str, choices: List[str], default: str = "") -> str:
        upper_map = {c.upper(): c for c in choices}
        while True:
            val = input(f"  {label} ({'/'.join(choices)}) [{default}]: ").strip().upper()
            if not val and default:
                return default
            if val in upper_map:
                return upper_map[val]
            print(f"    [!] Choose one of: {'/'.join(choices)}")

    def create_risk_entry(self) -> RiskEntry:
        print("\n" + "-" * 60)
        print("  NEW RISK ENTRY")
        print("-" * 60)
        entry = RiskEntry()
        entry.title           = self._prompt("Risk Title", "Ransomware via Phishing Email")
        entry.description     = self._prompt("Description", "Attacker delivers ransomware via phishing.")
        entry.asset_affected  = self._prompt("Asset Affected", "Email Gateway, Workstations")
        entry.department      = self._prompt("Department", "IT Operations")
        entry.risk_owner      = self._prompt("Risk Owner", "CISO")

        # NIST mapping
        print("\n  NIST CSF Functions: " + ", ".join(NIST_CSF.keys()))
        func_code = self._prompt_choice("Select NIST Function", list(NIST_CSF.keys()), "PR")
        print(f"\n  Categories for [{func_code}]:")
        cats = NIST_CSF[func_code]["categories"]
        for c, n in cats.items():
            print(f"    {c}  -  {n}")
        cat_code = self._prompt("Select Category code", list(cats.keys())[0])
        if not validate_category(cat_code):
            cat_code = list(cats.keys())[0]
        entry.nist_function = func_code
        entry.nist_category = cat_code.upper()

        # Threat linkage
        self.catalog.display()
        threat_id = self._prompt("Link Threat ID (or Enter to skip)", "")
        if threat_id:
            threat = self.catalog.get(threat_id)
            if threat:
                entry.threat_id   = threat.threat_id
                entry.threat_name = threat.name
            else:
                print(f"    [!] Threat '{threat_id}' not found.")

        # Scoring
        print("\n  Likelihood Scale:")
        for k, v in LIKELIHOOD_SCALE.items():
            print(f"    {k} - {v}")
        entry.likelihood = self._prompt_int("Likelihood", 1, 5, 3)
        print("\n  Impact Scale:")
        for k, v in IMPACT_SCALE.items():
            print(f"    {k} - {v}")
        entry.impact = self._prompt_int("Impact", 1, 5, 3)

        entry.existing_controls    = self._prompt("Existing Controls", "Email filtering, AV")
        entry.recommended_controls = self._prompt("Recommended Controls", "MFA, EDR, Security Training")
        entry.review_date          = self._prompt("Review Date (YYYY-MM-DD)", "2025-12-31")
        entry.status               = self._prompt_choice(
            "Status", ["Open", "Mitigated", "Accepted", "Transferred", "Closed"], "Open"
        )
        print(f"\n  [OK] Risk Score: {entry.risk_score}/25  Level: {entry.risk_level}")
        return entry


# =============================================================================
#  DEMO DATA  (auto-seeded on first run)
# =============================================================================

DEMO_RISKS = [
    {"title":"Ransomware via Phishing Email","description":"Employee opens malicious attachment delivering LockBit payload.","nist_function":"PR","nist_category":"PR.AT","threat_id":"TH-001","threat_name":"LockBit 3.0","likelihood":5,"impact":5,"existing_controls":"Basic email filtering, signature-based AV","recommended_controls":"AI-based email sandbox, Security Awareness Training, MFA","asset_affected":"Email Gateway, Employee Workstations","risk_owner":"CISO","department":"All Departments","review_date":"2025-06-30","status":"Open"},
    {"title":"Exposed RDP Port Exploited","description":"Brute-forced RDP session used to deploy Cl0p ransomware.","nist_function":"PR","nist_category":"PR.AA","threat_id":"TH-003","threat_name":"Cl0p","likelihood":4,"impact":5,"existing_controls":"Firewall rules (partially enforced)","recommended_controls":"Disable public RDP, VPN-only access, network segmentation","asset_affected":"Remote Desktop Servers","risk_owner":"IT Infrastructure Lead","department":"IT Operations","review_date":"2025-03-31","status":"Open"},
    {"title":"Unpatched VPN Appliance","description":"Known CVE in VPN appliance allows initial access for Akira ransomware.","nist_function":"ID","nist_category":"ID.RA","threat_id":"TH-008","threat_name":"Akira","likelihood":4,"impact":4,"existing_controls":"Quarterly patching cycle","recommended_controls":"Continuous vulnerability scanning, emergency patch SLA <48h","asset_affected":"Cisco AnyConnect VPN","risk_owner":"Network Security Manager","department":"Network Operations","review_date":"2025-04-15","status":"Open"},
    {"title":"No Offline Backup for Critical Servers","description":"Critical file servers have no offline backups, making recovery impossible after encryption.","nist_function":"RC","nist_category":"RC.RP","threat_id":None,"threat_name":"","likelihood":3,"impact":5,"existing_controls":"Online cloud backups (not air-gapped)","recommended_controls":"3-2-1 backup strategy, immutable backups, quarterly recovery tests","asset_affected":"File Servers, ERP Database","risk_owner":"IT Director","department":"IT Operations","review_date":"2025-05-01","status":"Open"},
    {"title":"Lack of Ransomware Incident Response Plan","description":"No ransomware-specific IR playbook exists, delaying containment.","nist_function":"RS","nist_category":"RS.MA","threat_id":None,"threat_name":"","likelihood":4,"impact":4,"existing_controls":"Generic IT incident response policy","recommended_controls":"Ransomware-specific playbook, tabletop exercises, legal/PR contacts","asset_affected":"All IT Systems","risk_owner":"CISO","department":"Security Operations","review_date":"2025-07-01","status":"Open"},
    {"title":"Insufficient Network Segmentation","description":"Flat network allows lateral movement across critical systems after compromise.","nist_function":"PR","nist_category":"PR.IR","threat_id":"TH-002","threat_name":"BlackCat (ALPHV)","likelihood":4,"impact":4,"existing_controls":"VLAN separation on some segments","recommended_controls":"Zero-trust micro-segmentation, endpoint isolation capability","asset_affected":"Core Network Infrastructure","risk_owner":"Network Security Manager","department":"Network Operations","review_date":"2025-08-01","status":"Open"},
    {"title":"Third-Party Vendor with Privileged Access","description":"Managed service provider has persistent privileged access; supply chain risk.","nist_function":"GV","nist_category":"GV.SC","threat_id":"TH-005","threat_name":"REvil (Sodinokibi)","likelihood":3,"impact":5,"existing_controls":"Vendor access agreement, quarterly review","recommended_controls":"Just-in-time privileged access, PAM tooling, vendor risk assessments","asset_affected":"All Managed Systems","risk_owner":"Third-Party Risk Manager","department":"Procurement & Risk","review_date":"2025-06-01","status":"Open"},
    {"title":"No Endpoint Detection & Response (EDR)","description":"Legacy AV provides no behavioural detection; ransomware execution goes undetected.","nist_function":"DE","nist_category":"DE.CM","threat_id":"TH-004","threat_name":"Hive","likelihood":5,"impact":4,"existing_controls":"Signature-based AV on all endpoints","recommended_controls":"Deploy EDR with ransomware rollback capability (e.g. CrowdStrike Falcon)","asset_affected":"All Employee Endpoints (2,400 devices)","risk_owner":"CISO","department":"Security Operations","review_date":"2025-04-30","status":"Open"},
    {"title":"Weak Password Policy / No MFA","description":"Accounts with weak passwords grant easy access via credential stuffing.","nist_function":"PR","nist_category":"PR.AA","threat_id":"TH-006","threat_name":"WannaCry","likelihood":5,"impact":3,"existing_controls":"Password policy (min 8 chars, annual rotation)","recommended_controls":"MFA on all critical systems, password manager, 16-char minimum, breach monitoring","asset_affected":"Active Directory, VPN, Email, Cloud Portals","risk_owner":"IT Security Manager","department":"IT Security","review_date":"2025-03-01","status":"Mitigated"},
    {"title":"Sensitive Data Stored Unencrypted","description":"PII and financial data stored in plaintext databases - worsens double-extortion leverage.","nist_function":"PR","nist_category":"PR.DS","threat_id":"TH-007","threat_name":"Royal Ransomware","likelihood":3,"impact":4,"existing_controls":"TLS in transit; no encryption at rest","recommended_controls":"Encrypt databases at rest (AES-256), tokenise PII, DLP policy","asset_affected":"Customer Database, Finance Systems","risk_owner":"Data Protection Officer","department":"Data Governance","review_date":"2025-09-01","status":"Open"},
]

DEMO_THREATS = [
    {"threat_id":"TH-001","name":"LockBit 3.0","family":"LockBit","description":"RaaS with double extortion. AES-256+RSA-2048 encryption.","attack_vector":"Phishing, RDP Exploitation, Compromised Credentials","target_sectors":["Finance","Healthcare","Manufacturing","Government"],"nist_functions_impacted":["ID","PR","DE","RS","RC"],"typical_ransom_usd":"$50,000 - $50,000,000","encryption_method":"AES-256 + RSA-2048","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1566","T1078","T1486","T1041","T1490"],"iocs":["lockbit3.onion","*.lockbit extension"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"]},
    {"threat_id":"TH-002","name":"BlackCat (ALPHV)","family":"BlackCat","description":"Rust-based cross-platform RaaS. ChaCha20+RSA-4096.","attack_vector":"Stolen Credentials, Phishing, Unpatched VPN","target_sectors":["Energy","Healthcare","Retail","Legal"],"nist_functions_impacted":["ID","PR","DE","RS","RC"],"typical_ransom_usd":"$1,000,000 - $5,000,000","encryption_method":"ChaCha20 + RSA-4096","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1190","T1078","T1486","T1485","T1489"],"iocs":["alphvmmm27o3abo3r2mlmjjiiqgmg65lchzxs4kszgfierq7uus7zmmqd.onion"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"]},
    {"threat_id":"TH-003","name":"Cl0p","family":"Cl0p","description":"Exploits zero-days in MOVEit and GoAnywhere file transfer tools.","attack_vector":"Zero-Day Exploitation, SQL Injection, Supply Chain","target_sectors":["Finance","Education","Government","Technology"],"nist_functions_impacted":["ID","PR","DE","RS"],"typical_ransom_usd":"$500,000 - $20,000,000","encryption_method":"RC4 + RSA-1024","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1190","T1567","T1486","T1005"],"iocs":["*.cl0p extension","CL0P^_-README.txt"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"]},
    {"threat_id":"TH-004","name":"Hive","family":"Hive","description":"RaaS targeting hospitals and critical infrastructure. Fast Golang-based encryptor.","attack_vector":"Phishing, RDP, VPN Vulnerabilities","target_sectors":["Healthcare","Critical Infrastructure","Education"],"nist_functions_impacted":["PR","DE","RS","RC"],"typical_ransom_usd":"$100,000 - $6,000,000","encryption_method":"Elliptic Curve + XOR","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1566","T1021","T1486","T1491"],"iocs":["*.hive extension","HOW_TO_DECRYPT.txt"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a"]},
    {"threat_id":"TH-005","name":"REvil (Sodinokibi)","family":"REvil","description":"High-profile RaaS behind Kaseya and JBS attacks. Supply chain specialist.","attack_vector":"Supply Chain, Phishing, Oracle WebLogic CVE","target_sectors":["Managed Service Providers","Food & Agriculture","Legal"],"nist_functions_impacted":["ID","PR","DE","RS","RC"],"typical_ransom_usd":"$5,000,000 - $70,000,000","encryption_method":"Salsa20 + Elliptic Curve Diffie-Hellman","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1195","T1059","T1486","T1490","T1082"],"iocs":["*.sodinokibi extension","readme-[random].txt"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a"]},
    {"threat_id":"TH-006","name":"WannaCry","family":"WannaCry","description":"Nation-state worm-ransomware exploiting EternalBlue (MS17-010). Affected 200,000+ systems.","attack_vector":"EternalBlue (MS17-010) SMB Exploit, Network Propagation","target_sectors":["Healthcare","Telecom","Government","Manufacturing"],"nist_functions_impacted":["ID","PR","DE"],"typical_ransom_usd":"$300 - $600 (Bitcoin)","encryption_method":"AES-128-CBC + RSA-2048","data_exfiltration":False,"double_extortion":False,"mitre_techniques":["T1210","T1486","T1027","T1016"],"iocs":["@Please_Read_Me@.txt","tasksche.exe"],"references":["https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware"]},
    {"threat_id":"TH-007","name":"Royal Ransomware","family":"Royal","description":"Operated by ex-Conti members. Uses callback phishing and partial encryption.","attack_vector":"Callback Phishing, Compromised RDP, Malvertising","target_sectors":["Healthcare","Critical Infrastructure","Education","Manufacturing"],"nist_functions_impacted":["PR","DE","RS","RC"],"typical_ransom_usd":"$250,000 - $2,000,000","encryption_method":"OpenSSL AES-256","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1566","T1021","T1486","T1083"],"iocs":["README.TXT",".royal extension"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"]},
    {"threat_id":"TH-008","name":"Akira","family":"Akira","description":"Emerging RaaS targeting Cisco VPN vulnerabilities. Double extortion with retro leak site.","attack_vector":"Cisco AnyConnect VPN CVE-2023-20269, Phishing","target_sectors":["Education","Finance","Manufacturing","Professional Services"],"nist_functions_impacted":["ID","PR","DE","RS"],"typical_ransom_usd":"$200,000 - $4,000,000","encryption_method":"ChaCha20 + RSA-4096","data_exfiltration":True,"double_extortion":True,"mitre_techniques":["T1190","T1078","T1486","T1570"],"iocs":["*.akira extension","akira_readme.txt"],"references":["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"]},
]


def seed_demo_data(register: RiskRegister) -> None:
    """Populate the register with 10 demonstration risk entries."""
    # Write threats.json if missing
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(THREATS_FILE):
        with open(THREATS_FILE, "w", encoding="utf-8") as fh:
            json.dump(DEMO_THREATS, fh, indent=2)
    for raw in DEMO_RISKS:
        entry = RiskEntry(**{k: v for k, v in raw.items() if k != "threat_id" or v is not None})
        if raw.get("threat_id") is None:
            entry.threat_id = None
        register.add(entry)
    print(f"  [OK] Seeded {len(DEMO_RISKS)} demo risk entries.\n")


# =============================================================================
#  CLI MENUS
# =============================================================================

def pause():
    input("\n  Press Enter to continue...")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner(stats: dict = None):
    print("\n  +==================================================================+")
    print("  |   ENTERPRISE RANSOMWARE ASSESSMENT TOOL                         |")
    print("  |   Corporate Risk Register  -  NIST CSF 2.0 Mapped               |")
    print("  +==================================================================+")
    print(f"  Version : {APP_VERSION}")
    if stats:
        c = stats["by_level"].get("CRITICAL", 0)
        h = stats["by_level"].get("HIGH", 0)
        print(f"  Risks   : {stats['total_risks']} total  |  CRITICAL: {c}  |  HIGH: {h}\n")


def menu_view(register: RiskRegister, reporter: Reporter) -> None:
    print("\n  VIEW OPTIONS")
    print("  1. All risks")
    print("  2. Filter by risk level  (CRITICAL / HIGH / MEDIUM / LOW)")
    print("  3. Filter by NIST function")
    print("  4. Filter by status")
    print("  5. Filter by department")
    print("  6. View single entry detail")
    print("  0. Back")
    choice = input("\n  > ").strip()
    if choice == "1":
        reporter.print_register(register.list_all())
    elif choice == "2":
        level = input("  Level: ").strip().upper()
        reporter.print_register(register.filter_by_level(level), f"RISKS - {level}")
    elif choice == "3":
        print("  Functions:", ", ".join(NIST_CSF.keys()))
        func = input("  Function code: ").strip().upper()
        reporter.print_register(register.filter_by_nist_function(func), f"RISKS - [{func}]")
    elif choice == "4":
        status = input("  Status: ").strip()
        reporter.print_register(register.filter_by_status(status), f"RISKS - {status}")
    elif choice == "5":
        dept = input("  Department: ").strip()
        reporter.print_register(register.filter_by_department(dept), f"RISKS - {dept}")
    elif choice == "6":
        risk_id = input("  Risk ID: ").strip().upper()
        entry = register.get(risk_id)
        reporter.print_entry(entry) if entry else print(f"  [!] Risk '{risk_id}' not found.")
    pause()


def menu_manage(register: RiskRegister, engine: AssessmentEngine, reporter: Reporter) -> None:
    print("\n  MANAGE OPTIONS")
    print("  1. Add new risk (interactive wizard)")
    print("  2. Update risk status")
    print("  3. Update risk score (likelihood / impact)")
    print("  4. Delete risk")
    print("  0. Back")
    choice = input("\n  > ").strip()
    if choice == "1":
        entry = engine.create_risk_entry()
        register.add(entry)
        print(f"\n  [OK] Risk [{entry.risk_id}] added.")
        reporter.print_entry(entry)
    elif choice == "2":
        risk_id = input("  Risk ID: ").strip().upper()
        statuses = ["Open", "Mitigated", "Accepted", "Transferred", "Closed"]
        new_s = input(f"  New status ({'/'.join(statuses)}): ").strip()
        if new_s not in statuses:
            print("  [!] Invalid status.")
        else:
            updated = register.update(risk_id, status=new_s)
            print(f"  [OK] Status updated." if updated else f"  [!] Risk '{risk_id}' not found.")
    elif choice == "3":
        risk_id = input("  Risk ID: ").strip().upper()
        entry = register.get(risk_id)
        if not entry:
            print(f"  [!] Risk '{risk_id}' not found.")
        else:
            try:
                l = int(input(f"  Likelihood (1-5) [{entry.likelihood}]: ") or entry.likelihood)
                i = int(input(f"  Impact     (1-5) [{entry.impact}]: ") or entry.impact)
                register.update(risk_id, likelihood=l, impact=i)
                entry = register.get(risk_id)
                print(f"  [OK] New score: {entry.risk_score}/25  Level: {entry.risk_level}")
            except ValueError:
                print("  [!] Invalid input.")
    elif choice == "4":
        risk_id = input("  Risk ID to delete: ").strip().upper()
        if input(f"  Delete {risk_id}? (yes/no): ").strip().lower() == "yes":
            print(f"  [OK] Deleted." if register.delete(risk_id) else f"  [!] Not found.")
    pause()


def menu_reports(register: RiskRegister, reporter: Reporter) -> None:
    print("\n  REPORT OPTIONS")
    print("  1. Summary dashboard (console)")
    print("  2. Export CSV")
    print("  3. Export JSON")
    print("  4. Export full text report")
    print("  5. Export CRITICAL & HIGH risks only (CSV)")
    print("  0. Back")
    choice = input("\n  > ").strip()
    entries = register.list_all()
    stats   = register.summary_stats()
    if choice == "1":
        reporter.print_summary(stats)
    elif choice == "2":
        reporter.export_csv(entries)
    elif choice == "3":
        reporter.export_json(entries)
    elif choice == "4":
        reporter.export_text_report(entries, stats)
    elif choice == "5":
        high = register.filter_by_level("CRITICAL") + register.filter_by_level("HIGH")
        reporter.export_csv(high, os.path.join(REPORTS_DIR, "critical_high_risks.csv"))
    pause()


# =============================================================================
#  ENTRY POINT
# =============================================================================

def main():
    register = RiskRegister()
    engine   = AssessmentEngine()
    reporter = Reporter()

    if not register.list_all():
        print_banner()
        print("  No risk data found. Loading demo data...")
        seed_demo_data(register)
        input("  Press Enter to open the main menu...")

    while True:
        clear()
        stats = register.summary_stats()
        print_banner(stats)
        print("  +------------------------------------------+")
        print("  |  MAIN MENU                               |")
        print("  +------------------------------------------+")
        print("  |  1. View / Filter Risk Register          |")
        print("  |  2. Add / Manage Risks                   |")
        print("  |  3. Reports & Exports                    |")
        print("  |  4. View NIST CSF Framework              |")
        print("  |  5. Browse Threat Catalog                |")
        print("  |  6. Summary Dashboard                    |")
        print("  |  0. Exit                                 |")
        print("  +------------------------------------------+")
        choice = input("\n  Select option: ").strip()
        if   choice == "1": menu_view(register, reporter)
        elif choice == "2": menu_manage(register, engine, reporter)
        elif choice == "3": menu_reports(register, reporter)
        elif choice == "4": display_framework(); pause()
        elif choice == "5": engine.catalog.display(); pause()
        elif choice == "6": reporter.print_summary(register.summary_stats()); pause()
        elif choice == "0": print("\n  Goodbye.\n"); sys.exit(0)
        else: print("  [!] Invalid option."); pause()


if __name__ == "__main__":
    main()
