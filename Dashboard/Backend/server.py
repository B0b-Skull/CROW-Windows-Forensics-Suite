#!/usr/bin/env python3
"""
Windows System Analysis, Diagnostics, Security & Forensics Dashboard Backend
File: Dashboard/Backend/server.py

Provides:
  1. Static web serving for the Forensic Workstation root directory (bound to 127.0.0.1 by default).
  2. Strict allowlist-based PowerShell Script Execution Engine (/api/scripts/run).
  3. Parameter validation, concurrency locking, timeout enforcement, and cancellation.
  4. SQLite operational persistence (Data/forensic_workstation.db) & audit logging (Logs/script_execution.log).
  5. Live telemetry & Obsidian Vault Markdown browser API (/api/data, /api/obsidian).
"""

import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG_PATH = BASE_DIR / "Config" / "script_registry.json"
LOG_DIR = BASE_DIR / "Logs"
DATA_DIR = BASE_DIR / "Data"
DB_PATH = DATA_DIR / "forensic_workstation.db"
UI_PREFS_PATH = DATA_DIR / "Config" / "ui_preferences.json"
MASTER_JSON_PATH = DATA_DIR / "Telemetry" / "master_dashboard_data.json"
OBSIDIAN_DIR = BASE_DIR / "ObsidianVault"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "script_execution.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Global execution state & lock to prevent conflicting concurrent collection jobs
EXEC_LOCK = threading.Lock()
CURRENT_JOB = {
    "running": False,
    "scriptId": None,
    "scriptName": None,
    "startedAt": None,
    "process": None
}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def atomic_write_text(target_path: Path, text: str):
    """Writes text to a .tmp file and atomically replaces target_path to prevent partial/corrupted files on crash."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(target_path.suffix + f".{os.getpid()}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target_path)
    except Exception:
        try:
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(text)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except Exception:
                    pass


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS script_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            script_id TEXT NOT NULL,
            script_name TEXT NOT NULL,
            parameters_json TEXT,
            started_at_utc TEXT NOT NULL,
            completed_at_utc TEXT,
            duration_sec REAL,
            exit_code INTEGER,
            status TEXT NOT NULL,
            output_preview TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS investigation_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at_utc TEXT NOT NULL,
            total_processes INTEGER,
            total_tcp_connections INTEGER,
            verified_binaries INTEGER,
            security_findings INTEGER,
            summary_json TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ui_preferences (
            pref_key TEXT PRIMARY KEY,
            pref_json TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def load_ui_preferences() -> dict:
    """Loads persisted table column order, visibility, and width settings from disk/SQLite."""
    prefs = read_json_safe(UI_PREFS_PATH)
    if isinstance(prefs, dict) and prefs:
        return prefs
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT pref_json FROM ui_preferences WHERE pref_key = 'table_preferences'")
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return json.loads(row[0])
    except Exception as e:
        logging.warning(f"Failed loading ui_preferences from SQLite: {e}")
    return {"tables": {}}


def save_ui_preferences(prefs: dict) -> dict:
    """Persists table column order, visibility, and width settings to disk and SQLite."""
    if not isinstance(prefs, dict):
        prefs = {"tables": {}}
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    prefs["updatedAtUtc"] = now_utc
    try:
        atomic_write_text(UI_PREFS_PATH, json.dumps(prefs, indent=2))
    except Exception as e:
        logging.warning(f"Failed saving UI_PREFS_PATH: {e}")
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO ui_preferences (pref_key, pref_json, updated_at_utc)
            VALUES ('table_preferences', ?, ?)
            ON CONFLICT(pref_key) DO UPDATE SET
                pref_json = excluded.pref_json,
                updated_at_utc = excluded.updated_at_utc
        """, (json.dumps(prefs), now_utc))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"Failed saving ui_preferences to SQLite: {e}")
    return prefs


def load_registry():
    if not CONFIG_PATH.exists():
        return {"Scripts": [], "SecurityPolicy": {}}
    with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def read_json_safe(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to parse JSON {path}: {e}")
        return None


def collect_obsidian_notes():
    vault_files = []
    if OBSIDIAN_DIR.exists():
        for md in sorted(OBSIDIAN_DIR.rglob("*.md")):
            rel = md.relative_to(OBSIDIAN_DIR).as_posix()
            try:
                content = md.read_text(encoding="utf-8-sig")
            except Exception:
                content = ""
            vault_files.append({
                "relativePath": rel,
                "fileName": md.name,
                "folder": md.parent.name if md.parent != OBSIDIAN_DIR else "Root",
                "modifiedLocal": datetime.fromtimestamp(md.stat().st_mtime).astimezone().isoformat(timespec="seconds"),
                "sizeBytes": md.stat().st_size,
                "content": content
            })
    return vault_files


def analyze_script_diagnostics(script_id, s_meta, exit_code, stdout_str, stderr_str, script_output_data):
    diag = {
        "hasIssue": False,
        "severity": "Info",
        "title": f"{script_id} Completed Successfully",
        "explanation": f"Executed '{s_meta.get('Name', script_id)}' with zero errors.",
        "recommendedFix": "",
        "commandPS51": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \".\\{s_meta.get('ScriptPath', '')}\"",
        "commandPS7": f"pwsh.exe -NoProfile -ExecutionPolicy Bypass -File \".\\{s_meta.get('ScriptPath', '')}\"",
        "technicalDetails": ""
    }

    # Check structured status inside script_output_data
    if isinstance(script_output_data, dict):
        st = str(script_output_data.get("Status", "")).strip()
        if st == "ElevationRequired":
            diag["hasIssue"] = True
            diag["severity"] = "Warning"
            diag["title"] = f"Administrator Privileges Required ({script_id})"
            diag["explanation"] = script_output_data.get("Explanation") or (
                "This operation modifies a protected machine-wide Windows Registry key (HKLM) or System Service (SCM), "
                "which Windows restricts to Administrator processes."
            )
            diag["recommendedFix"] = script_output_data.get("RecommendedFix") or (
                "1. Approve the Windows User Account Control (UAC) prompt when clicking 'Authorize & Execute', OR "
                "2. Right-click 'Start-Dashboard.cmd' -> 'Run as administrator', OR "
                "3. Copy the PowerShell command below and run it in an elevated PowerShell window."
            )
            if script_output_data.get("Command_PS51"):
                diag["commandPS51"] = script_output_data["Command_PS51"]
            if script_output_data.get("Command_PS7"):
                diag["commandPS7"] = script_output_data["Command_PS7"]
            return diag
        elif st == "NotApplicable":
            diag["hasIssue"] = True
            diag["severity"] = "Info"
            diag["title"] = f"No Change Needed ({script_output_data.get('Mode', 'Target Not Present')})"
            diag["explanation"] = script_output_data.get("Explanation") or "The target service or setting does not exist on this system."
            diag["recommendedFix"] = script_output_data.get("RecommendedFix") or "No action is required on this system."
            return diag
        elif st == "Error":
            diag["hasIssue"] = True
            diag["severity"] = "Error"
            diag["title"] = f"Execution Error in {script_id} ({s_meta.get('Name', '')})"
            diag["explanation"] = (
                script_output_data.get("Explanation")
                or script_output_data.get("ErrorMessage")
                or script_output_data.get("Message")
                or "The script reported an execution error."
            )
            diag["recommendedFix"] = script_output_data.get("RecommendedFix") or (
                "Verify target parameters (such as PID or file permissions) and run as Administrator if accessing protected system objects."
            )
            diag["technicalDetails"] = script_output_data.get("ErrorMessage") or script_output_data.get("Message") or ""
            return diag

    # Check non-zero exit code or stderr
    err_text = ((stderr_str or "") + "\n" + (stdout_str or "")).strip()
    if exit_code != 0 or (stderr_str and stderr_str.strip()):
        diag["hasIssue"] = True
        diag["severity"] = "Error" if exit_code != 0 else "Warning"
        diag["technicalDetails"] = err_text[:1000]

        if exit_code == -1:
            diag["title"] = f"Script Timeout ({script_id})"
            diag["explanation"] = f"The script exceeded its configured timeout ({s_meta.get('TimeoutSeconds', 60)}s) while querying system interfaces."
            diag["recommendedFix"] = "Retry with a smaller lookback window (e.g. DaysBack = 7) or increase TimeoutSeconds in Config/script_registry.json."
        elif re.search(r"Access is denied|UnauthorizedAccess|requires Administrator|Elevation", err_text, re.I):
            diag["title"] = f"Permission / Elevation Restricted ({script_id})"
            diag["explanation"] = "Windows denied access to a protected resource (such as HKLM registry keys, Security Event Log, or a Protected Process Light process)."
            diag["recommendedFix"] = "Right-click 'Start-Dashboard.cmd' or 'Run-ForensicAnalysis.cmd' and choose 'Run as administrator'."
        elif re.search(r"ParserError|TerminatorExpected|InvalidVariableReference", err_text, re.I):
            diag["title"] = f"PowerShell Parser / Encoding Issue ({script_id})"
            diag["explanation"] = "Windows PowerShell encountered a syntax or character-encoding issue while parsing the script."
            diag["recommendedFix"] = "Ensure the .ps1 file contains pure ASCII or UTF-8 with BOM so Windows PowerShell 5.1 parses string delimiters accurately."
        elif re.search(r"ExecutionPolicy|PSSecurityException", err_text, re.I):
            diag["title"] = f"PowerShell ExecutionPolicy Blocked ({script_id})"
            diag["explanation"] = "The local machine's Group Policy or ExecutionPolicy restricted running the PowerShell script."
            diag["recommendedFix"] = "Run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force' in PowerShell."
        else:
            diag["title"] = f"Script Reported Issue ({script_id} - Exit Code {exit_code})"
            diag["explanation"] = f"PowerShell returned exit code {exit_code}. See technical details below for the exact message."
            diag["recommendedFix"] = "Review the technical details below or run the command directly in PowerShell to inspect verbose output."

    return diag


def refresh_master_bundle():
    """Rebuilds master_dashboard_data.json and data.js after individual script runs."""
    legacy_path = BASE_DIR / "Data" / "Baselines" / "Initial_Backup_20261025" / "diagnostics_data.json"
    if not legacy_path.exists():
        legacy_path = BASE_DIR / "diagnostics_data.json"
    legacy = read_json_safe(legacy_path) or {}

    existing_master = read_json_safe(MASTER_JSON_PATH) or {}
    now_local = datetime.now().astimezone().isoformat(timespec="seconds")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    master = {
        "GeneratedAtLocal": now_local,
        "GeneratedAtUtc": now_utc,
        "TotalDurationSec": existing_master.get("TotalDurationSec", 0),
        "ScriptRunSummary": existing_master.get("ScriptRunSummary", []),
        "Hardware": read_json_safe(DATA_DIR / "Inventory" / "hardware_inventory_latest.json"),
        "Performance": read_json_safe(DATA_DIR / "Telemetry" / "performance_telemetry_latest.json"),
        "Processes": read_json_safe(DATA_DIR / "Inventory" / "process_inventory_latest.json"),
        "Services": read_json_safe(DATA_DIR / "Inventory" / "service_inventory_latest.json"),
        "Drivers": read_json_safe(DATA_DIR / "Inventory" / "driver_inventory_latest.json"),
        "Registry": read_json_safe(DATA_DIR / "Inventory" / "registry_persistence_latest.json"),
        "Network": read_json_safe(DATA_DIR / "Inventory" / "network_forensics_latest.json"),
        "Events": read_json_safe(DATA_DIR / "Telemetry" / "event_forensics_latest.json"),
        "Incidents": read_json_safe(DATA_DIR / "Investigations" / "incident_investigation_latest.json"),
        "CorrelatedEntities": read_json_safe(DATA_DIR / "Inventory" / "correlated_entities_latest.json"),
        "BinaryIntegrity": read_json_safe(DATA_DIR / "Inventory" / "binary_integrity_latest.json"),
        "SecurityFindings": read_json_safe(DATA_DIR / "Investigations" / "security_findings_latest.json"),
        "DeepPersistence": read_json_safe(DATA_DIR / "Investigations" / "deep_persistence_scriptblock_latest.json"),
        "SuperTimeline": read_json_safe(DATA_DIR / "Investigations" / "super_timeline_latest.json"),
        "MemoryForensics": read_json_safe(DATA_DIR / "Investigations" / "memory_crash_forensics_latest.json"),
        "ObsidianNotes": collect_obsidian_notes(),
        "LegacyBaselineAudit": {
            "ReportTitle": legacy.get("ReportTitle"),
            "GeneratedDate": legacy.get("GeneratedDate"),
            "SystemSummary": legacy.get("SystemSummary"),
            "ExecutiveFindings": legacy.get("ExecutiveFindings"),
            "LogonLagDetails": legacy.get("LogonLagDetails"),
            "ShutdownLagDetails": legacy.get("ShutdownLagDetails"),
            "ResourceBloatAnalysis": legacy.get("ResourceBloatAnalysis"),
            "NetworkSecurityAnalysis": legacy.get("NetworkSecurityAnalysis"),
            "ActionPlan": legacy.get("ActionPlan"),
        }
    }

    master_str = json.dumps(master, indent=2)
    atomic_write_text(MASTER_JSON_PATH, master_str)

    legacy_str = json.dumps(master["LegacyBaselineAudit"], indent=2)
    data_js_content = (
        f"// Auto-updated by Dashboard Backend at {now_local}\n"
        f"window.DIAGNOSTIC_DATA = {legacy_str};\n"
        f"window.FORENSIC_DATA = {master_str};\n"
    )
    atomic_write_text(BASE_DIR / "data.js", data_js_content)

    # Record snapshot summary in SQLite
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        tot_proc = ((master.get("CorrelatedEntities") or {}).get("Summary") or {}).get("TotalCorrelatedProcesses", 0)
        tot_tcp = ((master.get("Network") or {}).get("Summary") or {}).get("TotalTCPConnections", 0)
        tot_bin = ((master.get("BinaryIntegrity") or {}).get("Summary") or {}).get("TotalVerifiedBinaries", 0)
        tot_sec = ((master.get("SecurityFindings") or {}).get("SummaryCounts") or {}).get("TotalFindings", 0)
        cur.execute("""
            INSERT INTO investigation_snapshots (created_at_utc, total_processes, total_tcp_connections, verified_binaries, security_findings, summary_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now_utc, tot_proc, tot_tcp, tot_bin, tot_sec, json.dumps({"updatedAt": now_local})))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"SQLite snapshot insert error: {e}")

    return master


class ForensicDashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_json(self, status_code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path

        if route == "/api/status":
            reg = load_registry()
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM script_runs ORDER BY id DESC LIMIT 30")
            history = [dict(r) for r in cur.fetchall()]
            conn.close()
            self.send_json(200, {
                "status": "online",
                "serverTimeLocal": datetime.now().astimezone().isoformat(timespec="seconds"),
                "currentJob": {
                    "running": CURRENT_JOB["running"],
                    "scriptId": CURRENT_JOB["scriptId"],
                    "scriptName": CURRENT_JOB["scriptName"],
                    "startedAt": CURRENT_JOB["startedAt"]
                },
                "registry": reg,
                "executionHistory": history
            })
            return

        if route == "/api/data":
            if not MASTER_JSON_PATH.exists():
                master = refresh_master_bundle()
            else:
                master = read_json_safe(MASTER_JSON_PATH) or {}
            if isinstance(master, dict):
                master["UIPreferences"] = load_ui_preferences()
            self.send_json(200, master or {})
            return

        if route == "/api/preferences":
            self.send_json(200, load_ui_preferences())
            return

        if route == "/api/obsidian":
            vault_files = collect_obsidian_notes()
            self.send_json(200, {"vaultRoot": str(OBSIDIAN_DIR), "notes": vault_files})
            return

        if route == "/api/telemetry/live":
            live_path = DATA_DIR / "Performance" / "live_telemetry.json"
            live_data = read_json_safe(live_path) if live_path.exists() else {}
            self.send_json(200, live_data or {})
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        route = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            req_data = json.loads(raw_body)
        except Exception:
            self.send_json(400, {"error": "Invalid JSON request body."})
            return

        if route == "/api/preferences":
            saved = save_ui_preferences(req_data)
            self.send_json(200, {"status": "saved", "preferences": saved})
            return

        if route == "/api/scripts/cancel":
            proc = CURRENT_JOB.get("process")
            if CURRENT_JOB["running"] and proc:
                try:
                    proc.terminate()
                    logging.warning(f"Cancelled running script {CURRENT_JOB['scriptId']}")
                    self.send_json(200, {"status": "cancelled", "scriptId": CURRENT_JOB["scriptId"]})
                except Exception as e:
                    self.send_json(500, {"error": str(e)})
            else:
                self.send_json(200, {"status": "no_active_job"})
            return

        if route == "/api/scripts/run":
            script_id = str(req_data.get("scriptId", "")).strip()
            params = req_data.get("parameters") or {}

            reg = load_registry()
            script_map = {s["ScriptId"]: s for s in reg.get("Scripts", [])}

            # 1. Strict Allowlist Verification
            if script_id not in script_map:
                logging.error(f"Blocked unapproved script execution attempt: {script_id}")
                self.send_json(403, {
                    "error": f"Script ID '{script_id}' is not in the approved Config/script_registry.json allowlist."
                })
                return

            s_meta = script_map[script_id]
            rel_path = s_meta["ScriptPath"]
            full_script_path = (BASE_DIR / rel_path).resolve()

            # Ensure script resides strictly inside BASE_DIR / Scripts
            if not str(full_script_path).startswith(str((BASE_DIR / "Scripts").resolve())) or not full_script_path.exists():
                self.send_json(403, {"error": "Script path validation failed."})
                return

            # 2. Prevent Concurrent Conflicting Collection Jobs
            if not EXEC_LOCK.acquire(blocking=False):
                self.send_json(409, {
                    "error": f"Another script job ('{CURRENT_JOB['scriptId']}') is currently running. Please wait or cancel it."
                })
                return

            try:
                # 3. Validate & Sanitize Parameters against AllowedParameters
                allowed_params = set(s_meta.get("AllowedParameters", []))
                ps_args = [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-File", str(full_script_path)
                ]

                clean_params_log = {}
                for k, v in params.items():
                    if k not in allowed_params:
                        self.send_json(400, {"error": f"Parameter '{k}' is not permitted for script '{script_id}'."})
                        return
                    # Reject shell metacharacters
                    str_v = str(v)
                    if re.search(r"[;&|`$><\r\n]", str_v):
                        self.send_json(400, {"error": f"Parameter '{k}' contains disallowed characters."})
                        return
                    clean_params_log[k] = v
                    if isinstance(v, bool):
                        if v:
                            ps_args.append(f"-{k}")
                    else:
                        ps_args.extend([f"-{k}", str_v])

                start_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                t0 = time.time()
                CURRENT_JOB["running"] = True
                CURRENT_JOB["scriptId"] = script_id
                CURRENT_JOB["scriptName"] = s_meta["Name"]
                CURRENT_JOB["startedAt"] = start_utc

                logging.info(f"Executing allowlisted script {script_id} ({full_script_path}) with params={clean_params_log}")

                proc = subprocess.Popen(
                    ps_args,
                    cwd=str(BASE_DIR),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace"
                )
                CURRENT_JOB["process"] = proc

                timeout_sec = int(s_meta.get("TimeoutSeconds", 60))
                try:
                    stdout_str, stderr_str = proc.communicate(timeout=timeout_sec)
                    exit_code = proc.returncode
                    status_label = "Success" if exit_code == 0 else f"Failed (Exit {exit_code})"
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_str, stderr_str = proc.communicate()
                    exit_code = -1
                    status_label = f"Timeout ({timeout_sec}s)"

                duration = round(time.time() - t0, 2)
                end_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                # If script is not CORE-01, also re-run CORR-01 if PROC/SVC/REG/NET changed, and refresh master bundle
                if script_id in ("PROC-01", "SVC-01", "REG-01", "NET-01"):
                    corr_script = BASE_DIR / "Scripts" / "Core" / "Invoke-EntityCorrelation.ps1"
                    if corr_script.exists():
                        subprocess.run(
                            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(corr_script)],
                            cwd=str(BASE_DIR), timeout=45, capture_output=True
                        )

                master_data = refresh_master_bundle()

                # Read script's target output JSON if defined, or parse JSON from stdout
                out_json_rel = s_meta.get("OutputJsonPath")
                script_output_data = None
                if out_json_rel:
                    out_path = BASE_DIR / out_json_rel
                    if out_path.exists() and out_path.suffix.lower() == ".json":
                        script_output_data = read_json_safe(out_path)

                if script_output_data is None and stdout_str and stdout_str.strip().startswith("{"):
                    try:
                        script_output_data = json.loads(stdout_str.strip())
                    except Exception:
                        pass

                diagnostics = analyze_script_diagnostics(
                    script_id, s_meta, exit_code, stdout_str, stderr_str, script_output_data
                )
                if isinstance(script_output_data, dict) and script_output_data.get("Status") == "ElevationRequired":
                    status_label = "Elevation Required"
                elif isinstance(script_output_data, dict) and script_output_data.get("Status") == "NotApplicable":
                    status_label = "Not Applicable"

                combined_out = (stdout_str or "").strip()
                if stderr_str and stderr_str.strip():
                    combined_out += "\n[STDERR]\n" + stderr_str.strip()

                conn = sqlite3.connect(DB_PATH)
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO script_runs (script_id, script_name, parameters_json, started_at_utc, completed_at_utc, duration_sec, exit_code, status, output_preview)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    script_id, s_meta["Name"], json.dumps(clean_params_log),
                    start_utc, end_utc, duration, exit_code, status_label,
                    combined_out[:1500]
                ))
                conn.commit()
                conn.close()

                logging.info(f"Completed script {script_id} in {duration}s with status={status_label}")

                self.send_json(200, {
                    "scriptId": script_id,
                    "scriptName": s_meta["Name"],
                    "status": status_label,
                    "exitCode": exit_code,
                    "durationSec": duration,
                    "stdout": combined_out,
                    "scriptOutputJson": script_output_data,
                    "diagnostics": diagnostics,
                    "masterData": master_data
                })

            finally:
                CURRENT_JOB["running"] = False
                CURRENT_JOB["scriptId"] = None
                CURRENT_JOB["scriptName"] = None
                CURRENT_JOB["startedAt"] = None
                CURRENT_JOB["process"] = None
                EXEC_LOCK.release()
            return

        self.send_json(404, {"error": f"Unknown API endpoint {route}"})


def start_live_telemetry_daemon():
    """Starts a single persistent low-overhead PowerShell background loop that updates live_telemetry.json/.js every 3s."""
    script_path = BASE_DIR / "Scripts" / "Performance" / "Start-LiveTelemetryStream.ps1"
    if not script_path.exists():
        return None
    # Terminate any stale orphaned streamer from a previous session before spawning a new one
    pid_file = DATA_DIR / "Performance" / "live_streamer.pid"
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text(encoding="utf-8").strip())
            if old_pid > 0:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(old_pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3
                )
        except Exception:
            pass
    try:
        proc = subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", str(script_path),
                "-IntervalSeconds", "3",
                "-MaxSamples", "999999"
            ],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        )
        logging.info(f"Started persistent PowerShell Live Telemetry Streamer (PID {proc.pid})")
        return proc
    except Exception as exc:
        logging.warning(f"Could not start live telemetry streamer: {exc}")
        return None


def run_server(host="127.0.0.1", port=8765):
    init_db()
    refresh_master_bundle()
    telemetry_proc = start_live_telemetry_daemon()
    server = ThreadingHTTPServer((host, port), ForensicDashboardHandler)
    logging.info(f"Forensic Dashboard Server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down server.")
        server.server_close()
    finally:
        if telemetry_proc and telemetry_proc.poll() is None:
            try:
                telemetry_proc.terminate()
            except Exception:
                pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Windows Forensic Dashboard Backend Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    args = parser.parse_args()
    run_server(args.host, args.port)
