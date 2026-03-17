"""
╔══════════════════════════════════════════════════════════════╗
║       NET-FIRE-MONITOR  v3.9  –  core.py                    ║
║       Gemeinsame Engine – kein Code mehr doppelt            ║
╚══════════════════════════════════════════════════════════════╝

Enthält alle geteilten Klassen und Funktionen:
  Config, PacketInfo, FirewallRule
  FirewallEngine, EmailNotifier, ThreatIntelManager
  RuleEngine, SyslogExporter, NetworkMonitor
  Hilfs- und Geo-Funktionen
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import queue
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# ════════════════════════════════════════════════════════════════════════════
# PFAD-BASIS
# ════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR    = Path(__file__).parent.resolve()

# ── DATA_DIR: Alle veränderlichen Dateien (Gemini-Audit Fix 1) ─────────────
# Trennung: Code (SCRIPT_DIR, root-owned) vs. Daten (DATA_DIR, group-writable).
# Der Web-Prozess (User "netfiremon") darf nur DATA_DIR schreiben.
# DATA_DIR = SCRIPT_DIR / "data"  → wird in install.sh mit chmod 770 angelegt.
DATA_DIR      = SCRIPT_DIR / "data"

CONFIG_FILE   = DATA_DIR  / "net_fire_monitor_config.json"
LOG_FILE      = DATA_DIR  / "net_fire_monitor.log"
FIREWALL_LOG  = DATA_DIR  / "firewall.log"
STATE_FILE    = DATA_DIR  / "net_fire_monitor_state.json"
BASELINE_FILE = DATA_DIR  / "net_fire_monitor_baseline.json"
PERSIST_FILE  = DATA_DIR  / "net_fire_monitor_persist.json"
REPORT_DIR    = DATA_DIR  / "reports"
GEOIP_DB      = SCRIPT_DIR / "GeoLite2-City.mmdb"   # read-only, bleibt im Code-Dir

# ── IPC-Dateien (Monitor ↔ Web-Prozess) ────────────────────────────────────
LIVE_STATE_FILE = DATA_DIR / "net_fire_monitor_live.json"    # Monitor → Web (alle 2s)
CMD_QUEUE_DIR   = DATA_DIR / "cmd_queue"                     # Web → Monitor (je 1 Datei/Kommando)

# Maximales Alter einer gespeicherten Baseline in Sekunden (24 Stunden)
BASELINE_MAX_AGE_SECS = 86400

# DATA_DIR und CMD_QUEUE_DIR beim Import anlegen (idempotent)
DATA_DIR.mkdir(exist_ok=True)
CMD_QUEUE_DIR.mkdir(exist_ok=True)

# ════════════════════════════════════════════════════════════════════════════
# FIRST-RUN SETUP
# ════════════════════════════════════════════════════════════════════════════

SETUP_DONE_FILE = SCRIPT_DIR / ".nm_setup_done"

# BUG-B Fix: Modul-weiter Lock schützt alle Schreibzugriffe auf CONFIG_FILE
# und PERSIST_FILE gegen Race-Conditions wenn Monitor- und Web-Prozess
# (im Single-Process-Modus) gleichzeitig schreiben.
_CONFIG_WRITE_LOCK = threading.Lock()

REQUIRED_PACKAGES = [
    ("scapy",    "scapy"),
    ("rich",     "rich"),
    ("plyer",    "plyer"),
    ("geoip2",   "geoip2"),
    ("requests", "requests"),
]


def _pip_install(package: str) -> bool:
    cmd = [sys.executable, "-m", "pip", "install", package, "--quiet"]
    if platform.system() == "Linux":
        cmd.append("--break-system-packages")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except Exception:
        return False


def _check_npcap_windows() -> bool:
    import winreg
    for key_path in [r"SOFTWARE\Npcap", r"SOFTWARE\WOW6432Node\Npcap", r"SOFTWARE\WinPcap"]:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            return True
        except FileNotFoundError:
            continue
    return False


def first_run_setup() -> None:
    def _p(msg: str = "") -> None:
        for tag, esc in [("[bold cyan]","\033[1;36m"),("[bold green]","\033[1;32m"),
                         ("[bold yellow]","\033[1;33m"),("[bold red]","\033[1;31m"),
                         ("[bold white]","\033[1;37m"),("[dim]","\033[2m"),("[/]","\033[0m")]:
            msg = msg.replace(tag, esc)
        for t in ["[bold]","[/bold]","[cyan]","[green]","[yellow]","[red]","[white]",
                  "[/cyan]","[/green]","[/yellow]","[/red]","[/white]","[/dim]"]:
            msg = msg.replace(t, "")
        print(msg + "\033[0m")

    def _ask(prompt: str, default: str = "j") -> bool:
        hint = "[J/n]" if default == "j" else "[j/N]"
        try:
            ans = input(f"{prompt} {hint}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return default == "j"
        return (ans or default) in ("j", "y", "ja", "yes")

    if platform.system() == "Windows":
        subprocess.run(["cmd", "/c", "cls"], check=False)
    else:
        subprocess.run(["clear"], check=False)
    _p()
    _p("╔══════════════════════════════════════════════════════════╗")
    _p("║      NET-FIRE-MONITOR  v3.9  –  Ersteinrichtung         ║")
    _p("╚══════════════════════════════════════════════════════════╝")
    _p()
    _p("[bold cyan]Willkommen! Dieser Assistent richtet Net-Monitor ein.[/]")
    _p("[dim]Dieser Vorgang läuft nur beim ersten Start.[/]")
    _p()

    _p("━" * 58)
    _p("[bold white]SCHRITT 1/3 – Python-Pakete installieren[/]")
    _p("━" * 58)
    if platform.system() == "Linux":
        _p("[dim]💡 Empfohlen: Virtual Environment verwenden (python3 -m venv .venv)[/]")

    all_ok = True
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
            _p(f"  [bold green]✅  {pip_name} – bereits installiert[/]")
        except ImportError:
            _p(f"  ⏳  Installiere {pip_name} …")
            if _pip_install(pip_name):
                _p(f"  [bold green]✅  {pip_name} – erfolgreich installiert[/]")
            else:
                _p(f"  [bold red]❌  {pip_name} – fehlgeschlagen! Bitte manuell: pip install {pip_name}[/]")
                all_ok = False

    if not all_ok:
        _p("\n[bold yellow]⚠️  Einige Pakete konnten nicht installiert werden.[/]")
        input("Drücke ENTER zum Beenden …")
        sys.exit(1)

    _p()
    _p("━" * 58)
    _p("[bold white]SCHRITT 2/3 – Systemtreiber[/]")
    _p("━" * 58)
    if platform.system() == "Windows":
        if _check_npcap_windows():
            _p("[bold green]✅  Npcap ist bereits installiert.[/]")
        else:
            _p("[bold yellow]⚠️  Npcap nicht gefunden. Bitte von https://npcap.com installieren.[/]")
    else:
        _p(f"[bold green]✅  {platform.system()} – kein extra Treiber nötig.[/]")

    _p()
    _p("━" * 58)
    _p("[bold white]SCHRITT 3/3 – GeoLite2-City Datenbank[/]")
    _p("━" * 58)
    if GEOIP_DB.exists():
        _p(f"[bold green]✅  GeoLite2-City.mmdb gefunden.[/]")
    else:
        _p("[dim]Optional – Geo-IP-Daten (kostenlos bei maxmind.com)[/]")
        _p(f"  Datei GeoLite2-City.mmdb nach {GEOIP_DB} kopieren.")

    _p()
    _p("[bold green]✅  Einrichtung abgeschlossen![/]")
    input("Drücke ENTER um fortzufahren …")
    SETUP_DONE_FILE.write_text("setup completed")


# ════════════════════════════════════════════════════════════════════════════
# DATENSTRUKTUREN
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketInfo:
    timestamp:  str
    src_ip:     str
    dst_ip:     str
    protocol:   str
    src_port:   int | str
    dst_port:   int | str
    size:       int
    flags:      str = ""
    ip_version: int = 4


@dataclass
class FirewallRule:
    proto:   str = "any"
    port:    int = 0
    src_ip:  str = ""
    action:  str = "block"
    comment: str = ""


@dataclass
class Config:
    # Basis
    average_period:   int  = 60
    monitor_interval: int  = 10
    threshold:        int  = 20

    bpf_filter: str = field(default_factory=lambda: (
        "ip or ip6" if platform.system() == "Windows"
        else "tcp[tcpflags] & (tcp-syn) != 0 or icmp or udp"
    ))

    interface:  str  = ""
    interfaces: list = field(default_factory=list)

    notify_desktop: bool = True
    notify_log:     bool = True

    resolve_dns:    bool = True
    geo_lookup:     bool = True
    detect_portscan: bool = True
    portscan_limit: int  = 100

    whitelist: list = field(default_factory=list)
    blacklist: list = field(default_factory=list)

    export_csv:    bool = True
    export_json:   bool = False
    report_rotate: int  = 7

    firewall_mode:  str  = "monitor"
    firewall_rules: list = field(default_factory=list)

    email_enabled:   bool = False
    email_smtp:      str  = "smtp.gmail.com"
    email_port:      int  = 587
    email_user:      str  = ""
    email_password:  str  = ""
    email_recipient: str  = ""
    email_sender:    str  = ""

    threat_intel_enabled:         bool  = True
    threat_intel_auto_block:      bool  = False
    threat_intel_update_interval: int   = 3600
    threat_intel_feeds: list = field(default_factory=lambda: [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "https://cinsscore.com/list/ci-badguys.txt",
        "https://www.spamhaus.org/drop/drop.txt",
    ])

    syslog_enabled:  bool = False
    syslog_host:     str  = "localhost"
    syslog_port:     int  = 514
    syslog_protocol: str  = "udp"
    syslog_tag:      str  = "net-fire-monitor"
    syslog_facility: int  = 16

    # SECURITY (Gemini-Audit Fix 1): ProxyFix nur aktivieren wenn der Benutzer
    # explizit bestätigt dass ein Reverse-Proxy (nginx/caddy) vorgeschaltet ist.
    # Niemals automatisch aktivieren – sonst ist X-Forwarded-For fälschbar.
    behind_reverse_proxy: bool = False

    # SECURITY (Gemini-Audit Fix 2): Maximale Anzahl von IPs die im RAM
    # getrackt werden. Verhindert OOM bei SYN-Flood mit spoofed Source-IPs.
    max_tracked_ips: int = 50_000

    @classmethod
    def load(cls) -> "Config":
        if not CONFIG_FILE.exists():
            return cls()
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            valid = {f for f in cls.__dataclass_fields__}
            filtered = {k: v for k, v in data.items() if k in valid}
            obj = cls(**filtered)
            # SECURITY: E-Mail-Passwort aus separater Datei laden
            obj.email_password = _load_email_password()
            return obj
        except Exception:
            return cls()

    def save(self) -> None:
        data = asdict(self)
        # SECURITY: E-Mail-Passwort wird NICHT in der Config-Datei gespeichert.
        email_pw = data.pop("email_password", "")
        # BUG-B Fix: Lock verhindert Tear-Reads wenn Monitor und Web-Prozess
        # im Single-Process-Modus gleichzeitig speichern.
        with _CONFIG_WRITE_LOCK:
            tmp = CONFIG_FILE.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            if platform.system() != "Windows":
                tmp.chmod(0o600)
            tmp.replace(CONFIG_FILE)   # atomares Rename – kein halbfertiger Read möglich
        if platform.system() != "Windows":
            CONFIG_FILE.chmod(0o600)
        if email_pw:
            _save_email_password(email_pw)
        # BUG-04 Fix (v3.9): Warnung wenn öffentliche IPs in der Whitelist stehen.
        # Whitelisted IPs werden NIEMALS blockiert – auch nicht durch Threat-Intel.
        public_in_wl = [ip for ip in self.whitelist if not is_private_ip(ip) and validate_ip(ip)]
        if public_in_wl:
            logging.getLogger("NetMonitor").warning(
                "BUG-04-Warnung: %d öffentliche IP(s) in der Whitelist – diese IPs werden "
                "NIEMALS blockiert, auch nicht durch Threat-Intel: %s",
                len(public_in_wl), ", ".join(public_in_wl)
            )


# ════════════════════════════════════════════════════════════════════════════
# E-MAIL-PASSWORT  –  separate Datei, 0o600-Rechte
# ════════════════════════════════════════════════════════════════════════════

_EMAIL_PW_FILE = DATA_DIR / ".email_password"


def _save_email_password(password: str) -> None:
    """Speichert das E-Mail-Passwort separat mit restriktiven Dateiberechtigungen."""
    try:
        _EMAIL_PW_FILE.write_text(password, encoding="utf-8")
        if platform.system() != "Windows":
            _EMAIL_PW_FILE.chmod(0o600)
    except Exception as e:
        logging.getLogger("NetMonitor").warning("E-Mail-Passwort konnte nicht gespeichert werden: %s", e)


def _load_email_password() -> str:
    """Lädt das E-Mail-Passwort aus der separaten Datei."""
    # Umgebungsvariable hat Vorrang (z.B. für Docker/CI)
    env_pw = os.environ.get("NFM_EMAIL_PASSWORD", "")
    if env_pw:
        return env_pw
    if _EMAIL_PW_FILE.exists():
        try:
            return _EMAIL_PW_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return ""


# ════════════════════════════════════════════════════════════════════════════
# PASSWORT-HASHING  (scrypt – sicher gegen Brute-Force)
# ════════════════════════════════════════════════════════════════════════════

def _hash_password(password: str) -> str:
    import hashlib, os, base64
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt:" + base64.b64encode(salt + dk).decode()


def _verify_password(password: str, stored_hash: str) -> bool:
    import hashlib, base64
    if stored_hash.startswith("scrypt:"):
        try:
            raw = base64.b64decode(stored_hash[7:])
            salt, dk_stored = raw[:16], raw[16:]
            dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
            return hmac.compare_digest(dk, dk_stored)
        except Exception:
            return False
    # Legacy SHA-256
    return hmac.compare_digest(
        hashlib.sha256(password.encode()).hexdigest(), stored_hash
    )


def _setup_web_password() -> str:
    from rich.prompt import Prompt
    from rich.console import Console
    console = Console()
    while True:
        pw  = Prompt.ask("Web-Interface Passwort", password=True)
        pw2 = Prompt.ask("Passwort bestätigen",     password=True)
        if pw != pw2:
            console.print("[red]Passwörter stimmen nicht überein.[/red]")
            continue
        if len(pw) < 8:
            console.print("[yellow]Mindestens 8 Zeichen erforderlich.[/yellow]")
            continue
        h = _hash_password(pw)
        web_cfg = DATA_DIR / "net_fire_monitor_web_config.json"
        web_cfg.write_text(json.dumps({"password_hash": h}, indent=2))
        if platform.system() != "Windows":
            web_cfg.chmod(0o600)
        return h


# ════════════════════════════════════════════════════════════════════════════
# HILFS-FUNKTIONEN
# ════════════════════════════════════════════════════════════════════════════

# ── BUG-01 Fix (v3.9): Bounded LRU-DNS-Cache ──────────────────────────────
# Vorher: unbegrenztes dict → Memory Leak bei vielen verschiedenen IPs.
# Jetzt:  OrderedDict mit harter Obergrenze (10.000 Einträge) + LRU-Verdrängung.
_DNS_CACHE_MAXSIZE = 10_000
_dns_cache: dict[str, str] = {}   # bleibt für externen Import-Kompatibilität
_dns_lock = threading.Lock()

class _LRUDnsCache:
    """Thread-sicherer DNS-Cache mit LRU-Verdrängung. O(1) get + set."""
    def __init__(self, maxsize: int = _DNS_CACHE_MAXSIZE) -> None:
        from collections import OrderedDict as _OD
        self._data: _OD = _OD()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, ip: str):
        with self._lock:
            if ip in self._data:
                self._data.move_to_end(ip)   # LRU: als zuletzt genutzt markieren
                return self._data[ip]
        return None

    def set(self, ip: str, host: str) -> None:
        with self._lock:
            if ip in self._data:
                self._data.move_to_end(ip)
                self._data[ip] = host
            else:
                if len(self._data) >= self._maxsize:
                    self._data.popitem(last=False)   # O(1): ältesten Eintrag entfernen
                self._data[ip] = host

    def __contains__(self, ip: str) -> bool:
        with self._lock:
            return ip in self._data

    def __getitem__(self, ip: str) -> str:
        result = self.get(ip)
        if result is None:
            raise KeyError(ip)
        return result

_dns_lru = _LRUDnsCache(_DNS_CACHE_MAXSIZE)


def resolve_hostname(ip: str) -> str:
    cached = _dns_lru.get(ip)
    if cached is not None:
        return cached
    # BUG-TI4 Fix: socket.setdefaulttimeout() modifiziert globalen Zustand und ist
    # nicht thread-safe. Bei gleichzeitiger DNS-Auflösung aus mehreren Threads
    # können sich Timeouts gegenseitig überschreiben.
    # Lösung: eigenen Socket mit Timeout öffnen statt den globalen Default zu ändern.
    try:
        # getaddrinfo mit kurzer Verbindung ist nicht möglich – wir nutzen
        # einen Wrapper-Thread mit join(timeout) für echte Thread-Isolation.
        result = [ip]
        def _lookup():
            try:
                result[0] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
        t = threading.Thread(target=_lookup, daemon=True)
        t.start()
        t.join(timeout=0.5)
        host = result[0]
    except Exception:
        host = ip
    _dns_lru.set(ip, host)
    # Rückwärtskompatibilität: auch altes dict befüllen (wird in terminal.py gelesen)
    with _dns_lock:
        _dns_cache[ip] = host
    return host


def validate_ip(ip: str) -> bool:
    if not ip or len(ip) > 45:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


_geo_reader = None
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_OK = True
    if GEOIP_DB.exists():
        _geo_reader = geoip2.database.Reader(str(GEOIP_DB))
except ImportError:
    GEOIP_OK = False


def geo_lookup(ip: str) -> str:
    if _geo_reader is None:
        return "–"
    try:
        r = _geo_reader.city(ip)
        city    = r.city.name or ""
        country = r.country.iso_code or ""
        if city and country:
            city_short = city[:10] + "…" if len(city) > 10 else city
            return f"{city_short}, {country}"
        return country or "–"
    except Exception:
        return "–"


_NEUTRAL_COUNTRIES = {
    "DE","US","NL","GB","FR","SE","CH","AT","IE",
    "FI","DK","NO","BE","LU","CA","AU","JP","SG",
}


def geo_color(cc: str) -> str:
    if cc in ("–",""):  return "dim"
    if cc in _NEUTRAL_COUNTRIES: return "green"
    return "yellow"


def enrich_ip(ip: str) -> dict:
    if not validate_ip(ip):
        return {"hostname":"–","geo":"–","org":"–","whois_raw":"–","threat_intel":False}
    result = {"hostname":"–","geo":"–","org":"–","whois_raw":"–","threat_intel":False}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3.0)
    try:
        result["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result["hostname"] = "Nicht auflösbar"
    finally:
        socket.setdefaulttimeout(old)
    try:
        if _geo_reader:
            r = _geo_reader.city(ip)
            city    = r.city.name    or ""
            country = r.country.name or ""
            iso     = r.country.iso_code or ""
            result["geo"] = f"{city}, {country} ({iso})" if city else f"{country} ({iso})"
    except Exception:
        pass
    # BUG-X2 Fix: nslookup-subprocess entfernt.
    # socket.gethostbyaddr() liefert denselben Hostnamen ohne externe Abhängigkeit
    # und ohne 5s blockierenden subprocess-Aufruf.
    # Org/ASN-Info wird weiterhin per whois ermittelt (Linux/macOS only).
    if platform.system() in ("Linux","Darwin"):
        try:
            r = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=8)
            for line in r.stdout.splitlines():
                low = line.lower().strip()
                if any(k in low for k in ("orgname:","org-name:","netname:","descr:","owner:","organization:")):
                    val = line.split(":",1)[1].strip() if ":" in line else ""
                    if val and len(val) > 2:
                        result["org"] = val
                        break
        except Exception:
            pass
    return result


try:
    from plyer import notification as plyer_notify
    PLYER_OK = True
except ImportError:
    PLYER_OK = False

_console_ref = None  # wird von main() gesetzt

def send_notification(title: str, message: str, timeout: int = 10) -> None:
    if PLYER_OK:
        try:
            plyer_notify.notify(title=title, message=message, timeout=timeout)
            return
        except Exception:
            pass
    print(f"\n🔔  {title}: {message}")


def _fmt_bps(bps: float) -> str:
    if bps >= 1_000_000: return f"{bps/1_000_000:.1f} MB/s"
    if bps >= 1_000:     return f"{bps/1_000:.1f} KB/s"
    return f"{bps:.0f} B/s"


# ════════════════════════════════════════════════════════════════════════════
# STATE  (gemeinsamer Snapshot zwischen Terminal- und Web-Interface)
# ════════════════════════════════════════════════════════════════════════════

_firewall:     Optional["FirewallEngine"]     = None
_email:        Optional["EmailNotifier"]      = None
_threat_intel: Optional["ThreatIntelManager"] = None
_rule_engine:  Optional["RuleEngine"]         = None
_syslog:       Optional["SyslogExporter"]     = None


KNOWN_SERVICES = {
    443:"HTTPS", 80:"HTTP", 53:"DNS", 22:"SSH", 21:"FTP",
    25:"SMTP", 3389:"RDP", 3306:"MySQL", 8080:"HTTP-Alt",
    67:"DHCP", 68:"DHCP", 123:"NTP",
}


def save_state(mon: "NetworkMonitor") -> None:
    """Speichert vollständigen Snapshot (Dashboard-Anzeige, Web-Interface)."""
    try:
        alerts: list[str] = []
        if LOG_FILE.exists():
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            alerts = [l for l in lines if "WARNING" in l or "ERROR" in l][-200:]

        blocked: list[str] = []
        if _firewall:
            with _firewall._lock:
                blocked = list(_firewall.blocked_ips)

        ti_count = _threat_intel.get_count() if _threat_intel else 0

        with mon._lock:
            ip_total    = mon._ip_total.as_dict()
            port_total  = dict(mon._port_total)
            proto_total = dict(mon._proto_total)
            raw_pkts    = list(mon.recent_packets)[-50:]
            alert_list  = list(mon.alerts)[:50]

        def _geo_for(ip: str) -> str:
            if is_private_ip(ip): return "LAN"
            if mon.cfg.geo_lookup: return geo_lookup(ip)
            return "–"

        recent_pkts = [dict(asdict(p), geo=_geo_for(p.src_ip)) for p in raw_pkts]
        top_talkers = sorted(ip_total.items(), key=lambda x: -x[1])[:15]
        top_ports   = sorted(port_total.items(), key=lambda x: -x[1])[:10]

        state = {
            "saved_at":      datetime.now().isoformat(),
            "saved_by":      "terminal",
            "firewall_mode": mon.cfg.firewall_mode,
            "interface":     mon.cfg.interface or "alle",
            "threshold":     mon.cfg.threshold,
            "baseline_pps":  round(mon.baseline_pps, 2),
            "baseline_bps":  round(mon.baseline_bps, 2),
            "alert_count":   mon.alert_count,
            "ti_count":      ti_count,
            "blocked_ips":   blocked,
            "top_talkers": [
                {"ip": ip, "count": c,
                 "host": resolve_hostname(ip) if mon.cfg.resolve_dns else "–",
                 "geo":  _geo_for(ip), "private": is_private_ip(ip)}
                for ip, c in top_talkers
            ],
            "top_ports": [
                {"port": p, "count": c,
                 "service": KNOWN_SERVICES.get(int(p) if str(p).isdigit() else 0, "–")}
                for p, c in top_ports
            ],
            "proto_counts":   proto_total,
            "recent_packets": recent_pkts,
            "recent_alerts":  alert_list,
            "log_alerts":     alerts[-50:],
        }

        STATE_FILE.write_text(
            json.dumps(state, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
    except Exception as e:
        logging.getLogger("NetMonitor").error("Fehler beim Speichern des States: %s", e)

    # Baseline und Persistenz-Daten separat speichern
    save_baseline(mon)
    save_persist()


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


# ════════════════════════════════════════════════════════════════════════════
# BASELINE  –  persistente Speicherung & Wiederherstellung
# ════════════════════════════════════════════════════════════════════════════

def save_baseline(mon: "NetworkMonitor") -> None:
    """
    Speichert die aktuelle Baseline in BASELINE_FILE.
    Wird beim sauberen Beenden und alle 10 Minuten im laufenden Betrieb aufgerufen.
    """
    try:
        data = {
            "saved_at":    datetime.now().isoformat(),
            "baseline_pps": round(mon.baseline_pps, 4),
            "baseline_bps": round(mon.baseline_bps, 4),
        }
        BASELINE_FILE.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
    except Exception as e:
        logging.getLogger("NetMonitor").warning("Baseline-Speicherung fehlgeschlagen: %s", e)


def load_baseline() -> tuple[float, float] | None:
    """
    Lädt die gespeicherte Baseline wenn sie nicht älter als BASELINE_MAX_AGE_SECS ist.
    Gibt (baseline_pps, baseline_bps) zurück, oder None wenn keine gültige Baseline vorhanden.
    """
    if not BASELINE_FILE.exists():
        return None
    try:
        data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        saved_at = datetime.fromisoformat(data["saved_at"])
        age_secs = (datetime.now() - saved_at).total_seconds()
        if age_secs > BASELINE_MAX_AGE_SECS:
            logging.getLogger("NetMonitor").info(
                "Gespeicherte Baseline ist %.1f Stunden alt – wird neu gemessen.",
                age_secs / 3600
            )
            return None
        pps = float(data["baseline_pps"])
        bps = float(data["baseline_bps"])
        logging.getLogger("NetMonitor").info(
            "Baseline aus Snapshot geladen (%.0f Min. alt): %.2f pps | %.0f B/s",
            age_secs / 60, pps, bps
        )
        return pps, bps
    except Exception as e:
        logging.getLogger("NetMonitor").warning("Baseline-Laden fehlgeschlagen: %s", e)
        return None


# ════════════════════════════════════════════════════════════════════════════
# PERSISTENZ  –  Block-IPs und Firewall-Regeln nach Neustart wiederherstellen
# ════════════════════════════════════════════════════════════════════════════

def save_persist() -> None:
    """
    Speichert alle Daten die nach einem Neustart wiederhergestellt werden sollen:
      - Manuell blockierte IPs (aus FirewallEngine)
      - Benutzerdefinierte Firewall-Regeln (aus Config)
    Whitelist und Blacklist sind bereits in der Config gespeichert und
    werden automatisch beim Laden der Config wiederhergestellt.
    """
    try:
        blocked: list[str] = []
        if _firewall:
            with _firewall._lock:
                blocked = list(_firewall.blocked_ips)

        # BUG-B Fix: Config unter dem globalen Write-Lock lesen damit kein
        # Tear-Read entsteht wenn Config.save() gleichzeitig schreibt.
        with _CONFIG_WRITE_LOCK:
            cfg = Config.load()

        data = {
            "saved_at":      datetime.now().isoformat(),
            "blocked_ips":   blocked,
            "firewall_rules": cfg.firewall_rules,
            "whitelist":      cfg.whitelist,
            "blacklist":      cfg.blacklist,
        }
        # Atomares Schreiben über tmp → rename (wie CMD-Queue und Config.save)
        tmp = PERSIST_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        if platform.system() != "Windows":
            tmp.chmod(0o600)
        tmp.replace(PERSIST_FILE)
    except Exception as e:
        logging.getLogger("NetMonitor").warning("Persistenz-Speicherung fehlgeschlagen: %s", e)


def restore_on_startup(fw: "FirewallEngine") -> dict:
    """
    Stellt nach einem Neustart / Stromausfall wieder her:
      - Alle manuell blockierten IPs → werden sofort in iptables/netsh eingetragen
      - Benutzerdefinierte Firewall-Regeln → werden in die Config zurückgeschrieben
      - Whitelist / Blacklist → werden in die Config zurückgeschrieben (falls abweichend)

    Gibt ein Dict mit Statistiken zurück:
      {"restored_blocks": N, "restored_rules": N, "whitelist": N, "blacklist": N}
    """
    log = logging.getLogger("NetMonitor")
    stats = {"restored_blocks": 0, "restored_rules": 0, "whitelist": 0, "blacklist": 0}

    if not PERSIST_FILE.exists():
        return stats

    try:
        data = json.loads(PERSIST_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Persistenz-Datei konnte nicht gelesen werden: %s", e)
        return stats

    # ── 1. Blockierte IPs wiederherstellen ───────────────────────────────
    blocked_ips: list[str] = data.get("blocked_ips", [])
    cfg = Config.load()

    for ip in blocked_ips:
        if not validate_ip(ip):
            continue
        # Nicht blockieren wenn die IP inzwischen auf der Whitelist steht
        if ip in cfg.whitelist:
            log.info("Restore: %s übersprungen – steht auf Whitelist", ip)
            continue
        if is_private_ip(ip):
            log.info("Restore: %s übersprungen – private IP", ip)
            continue
        # Direkt in die blocked_ips-Menge eintragen und Firewall-Regel setzen
        with fw._lock:
            fw.blocked_ips.add(ip)
        try:
            fw._action_queue.put_nowait(("block", ip, "Wiederhergestellt nach Neustart"))
            stats["restored_blocks"] += 1
        except queue.Full:
            log.warning("Restore: Queue voll, Block für %s verworfen", ip)

    if stats["restored_blocks"] > 0:
        log.info("Restore: %d blockierte IP(s) wiederhergestellt.", stats["restored_blocks"])

    # ── 2. Firewall-Regeln sicherstellen ─────────────────────────────────
    # Die Regeln stehen bereits in der Config – RuleEngine wird beim Start
    # geladen. Hier prüfen wir nur ob die persist-Datei neuere Regeln hat
    # (z.B. wenn die Config-Datei beim Absturz nicht vollständig gespeichert wurde).
    persisted_rules: list[dict] = data.get("firewall_rules", [])
    if persisted_rules and persisted_rules != cfg.firewall_rules:
        cfg.firewall_rules = persisted_rules
        cfg.save()
        stats["restored_rules"] = len(persisted_rules)
        log.info("Restore: %d Firewall-Regel(n) aus Persistenz-Snapshot wiederhergestellt.",
                 stats["restored_rules"])

    # ── 3. Whitelist / Blacklist sicherstellen ───────────────────────────
    persisted_wl: list[str] = data.get("whitelist", [])
    persisted_bl: list[str] = data.get("blacklist", [])

    cfg_changed = False
    if persisted_wl and persisted_wl != cfg.whitelist:
        cfg.whitelist = persisted_wl
        stats["whitelist"] = len(persisted_wl)
        cfg_changed = True
    if persisted_bl and persisted_bl != cfg.blacklist:
        cfg.blacklist = persisted_bl
        stats["blacklist"] = len(persisted_bl)
        cfg_changed = True
    if cfg_changed:
        cfg.save()
        log.info("Restore: Whitelist (%d) und Blacklist (%d) aus Persistenz wiederhergestellt.",
                 stats["whitelist"], stats["blacklist"])

    return stats


def rotate_reports(days: int) -> None:
    if not REPORT_DIR.exists():
        return
    cutoff = time.time() - days * 86400
    for f in REPORT_DIR.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════════════════
# IPC  –  Monitor-Prozess ↔ Web-Prozess  (Gemini-Audit Fix 1)
#
# Problem: Zwei isolierte Prozesse teilen keinen Arbeitsspeicher.
#   _mon_ref ist im Gunicorn-Worker immer None.
#   Firewall-Aktionen aus dem Web würden als unprivilegierter User scheitern.
#
# Lösung: Datei-basierte Kommunikation über SCRIPT_DIR:
#   LIVE_STATE_FILE  Monitor → Web   (alle 2s, Live-Dashboard-Daten)
#   CMD_QUEUE_DIR    Web → Monitor   (je 1 Datei/Kommando, race-condition-frei)
# ════════════════════════════════════════════════════════════════════════════

# Intervall für Live-State-Export in Sekunden
LIVE_STATE_INTERVAL = 2.0


def save_live_state(mon: "NetworkMonitor") -> None:
    """
    Schreibt einen kompakten Live-Snapshot in LIVE_STATE_FILE.
    Wird vom Monitor-Prozess alle LIVE_STATE_INTERVAL Sekunden aufgerufen.
    Der Web-Prozess liest diese Datei für /api/status.
    Atomares Schreiben über temporäre Datei verhindert halbfertige Reads.
    """
    try:
        fw = _firewall
        blocked: list[str] = []
        if fw:
            with fw._lock:
                blocked = list(fw.blocked_ips)

        # BUG-TI5 Fix: IPs und CIDR-Netze separat zählen für ehrliche Dashboard-Anzeige.
        if _threat_intel:
            ti_ip_count, ti_cidr_count = _threat_intel.get_count_detail()
            ti_count = ti_ip_count + ti_cidr_count
        else:
            ti_ip_count = ti_cidr_count = ti_count = 0

        with mon._lock:
            ip_total    = mon._ip_total.as_dict()
            port_total  = dict(mon._port_total)
            proto_total = dict(mon._proto_total)
            raw_pkts    = list(mon.recent_packets)[-20:]
            alert_list  = list(mon.alerts)[:10]
            pps = mon._last_pps
            bps = mon._last_bps

        def _geo_for(ip: str) -> str:
            if is_private_ip(ip): return "LAN"
            if mon.cfg.geo_lookup: return geo_lookup(ip)
            return "–"

        top_talkers = sorted(ip_total.items(), key=lambda x: -x[1])[:10]

        state = {
            "ts":            time.time(),
            "firewall_mode": mon.cfg.firewall_mode,
            "interface":     mon.cfg.interface or "alle",
            "threshold":     mon.cfg.threshold,
            "baseline_pps":  round(mon.baseline_pps, 2),
            "baseline_bps":  round(mon.baseline_bps, 2),
            "pps":           round(pps, 2),
            "bps":           round(bps, 2),
            "alert_count":   mon.alert_count,
            "ti_count":      ti_count,
            "ti_ip_count":   ti_ip_count,
            "ti_cidr_count": ti_cidr_count,
            "blocked_ips":   blocked,
            "blocked_count": len(blocked),
            "top_talkers": [
                {"ip": ip, "count": c,
                 "host": resolve_hostname(ip) if mon.cfg.resolve_dns else "–",
                 "geo":  _geo_for(ip), "private": is_private_ip(ip)}
                for ip, c in top_talkers
            ],
            "top_ports": [
                {"port": p, "count": c,
                 "service": KNOWN_SERVICES.get(int(p) if str(p).isdigit() else 0, "–")}
                for p, c in sorted(port_total.items(), key=lambda x: -x[1])[:8]
            ],
            "protos":         proto_total,
            "recent_packets": [
                dict(asdict(p), geo=_geo_for(p.src_ip)) for p in raw_pkts
            ],
            "recent_alerts": alert_list,
            "muted_ips":     list(mon.get_muted_ips().keys()),
            "alert_cooldown": mon._alert_cooldown_secs,
            "geo_db_missing": not GEOIP_DB.exists(),
        }

        # Atomares Schreiben: erst tmp, dann rename.
        # 0o640: Monitor (root) erstellt die Datei, Web-User (netfiremon group) liest sie.
        # Andere Systembenutzer haben keinen Lesezugriff auf Dashboard-Statistiken.
        # (Gemini-Audit Fix 4 + Feinschliff Finding 1)
        tmp = LIVE_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(state, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        if platform.system() != "Windows":
            tmp.chmod(0o640)
        tmp.replace(LIVE_STATE_FILE)

    except Exception as e:
        logging.getLogger("NetMonitor").debug("save_live_state: %s", e)


def read_live_state() -> dict:
    """
    Liest den Live-Snapshot. Vom Web-Prozess für /api/status verwendet.
    Gibt leeres Dict zurück wenn die Datei fehlt oder älter als 30s ist.
    """
    if not LIVE_STATE_FILE.exists():
        return {}
    try:
        data = json.loads(LIVE_STATE_FILE.read_text(encoding="utf-8"))
        # Wenn Datei älter als 30s → Monitor läuft nicht
        if time.time() - data.get("ts", 0) > 30:
            return {}
        return data
    except Exception:
        return {}


class CommandQueue:
    """
    Directory-basierte Kommando-Queue für Web → Monitor IPC.
    (Gemini-Audit Fix 2: Race-Condition-freie Implementierung)

    WARUM ein Verzeichnis statt einer Datei:
      Eine einzelne gemeinsame Datei hat eine klassische Race-Condition:
        1. Web liest leere Datei
        2. Monitor löscht Datei
        3. Web schreibt neues Kommando → geht verloren
      Mit je einer Datei pro Kommando gibt es keine Konflikte:
        Web schreibt cmd_<uuid>.json (atomares rename)
        Monitor liest alle cmd_*.json, verarbeitet und löscht sie einzeln

    Unterstützte Aktionen:
      block, unblock, mute, unmute, set_cooldown,
      whitelist_add, whitelist_remove,
      blacklist_add, blacklist_remove,
      rule_add, rule_delete,
      reload_config   ← NEU: Config-Reload (Gemini-Audit Fix 3)
    """

    @classmethod
    def push(cls, command: dict) -> bool:
        """
        Schreibt ein Kommando als eigene JSON-Datei in CMD_QUEUE_DIR.
        Thread-sicher und prozess-sicher (keine Race-Condition).
        """
        try:
            import uuid as _uuid
            command["queued_at"] = time.time()

            # Schutz vor Queue-Flooding (Finding 2):
            # Auch ein eingeloggter Admin könnte per Skript Millionen Kommandos
            # senden und die Inodes des Dateisystems erschöpfen.
            # 500 wartende Kommandos sind mehr als genug für normalen Betrieb.
            try:
                queue_size = sum(1 for _ in CMD_QUEUE_DIR.glob("cmd_*.json"))
                if queue_size >= 500:
                    logging.getLogger("NetMonitor").warning(
                        "CommandQueue voll (%d Einträge) – Kommando '%s' abgelehnt.",
                        queue_size, command.get("action", "?")
                    )
                    return False
            except Exception:
                pass  # Glob-Fehler → im Zweifel trotzdem schreiben

            fname = CMD_QUEUE_DIR / f"cmd_{_uuid.uuid4().hex}.json"
            tmp   = fname.with_suffix(".tmp")
            tmp.write_text(json.dumps(command, ensure_ascii=False), encoding="utf-8")
            if platform.system() != "Windows":
                # 0o640: nur netfiremon (owner) und root (via group) dürfen lesen.
                # 0o664 wäre world-readable – unbeteiligte Systemuser könnten
                # Firewall-Kommandos mitlesen. Root ignoriert Dateirechte sowieso.
                tmp.chmod(0o640)
            tmp.replace(fname)
            return True
        except Exception as e:
            logging.getLogger("NetMonitor").warning("CommandQueue.push: %s", e)
            return False

    @classmethod
    def pop_all(cls) -> list[dict]:
        """
        Liest und verarbeitet alle wartenden Kommandos.
        Nur vom Monitor-Prozess (root) aufgerufen.
        Jede Datei wird sofort nach dem Lesen gelöscht → keine Race-Condition.
        Veraltete Kommandos (> 60s) werden verworfen.
        """
        if not CMD_QUEUE_DIR.exists():
            return []
        commands: list[dict] = []
        now = time.time()
        try:
            for fpath in sorted(CMD_QUEUE_DIR.glob("cmd_*.json")):
                try:
                    cmd = json.loads(fpath.read_text(encoding="utf-8"))
                    fpath.unlink(missing_ok=True)
                    # Veraltete Kommandos verwerfen
                    if now - cmd.get("queued_at", 0) < 60:
                        commands.append(cmd)
                except Exception as e:
                    logging.getLogger("NetMonitor").warning(
                        "CommandQueue.pop_all: Fehler bei %s: %s", fpath.name, e
                    )
                    try:
                        fpath.unlink(missing_ok=True)
                    except Exception:
                        pass
        except Exception as e:
            logging.getLogger("NetMonitor").warning("CommandQueue.pop_all: %s", e)
        return commands


# ════════════════════════════════════════════════════════════════════════════
# FIREWALL ENGINE
# ════════════════════════════════════════════════════════════════════════════

class FirewallEngine:
    def __init__(self) -> None:
        self.system = platform.system()
        from logging.handlers import RotatingFileHandler
        self._fw_logger = logging.getLogger("Firewall")
        fh = RotatingFileHandler(
            FIREWALL_LOG, maxBytes=2*1024*1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self._fw_logger.addHandler(fh)
        self._fw_logger.setLevel(logging.DEBUG)

        self.blocked_ips: set[str] = set()
        self._lock = threading.Lock()
        self._block_timestamps: dict[str, float] = {}
        self._rate_limit_seconds: float = 10.0
        self._max_blocks_per_minute: int = 30
        self._blocks_this_minute: list[float] = []

        self._action_queue: queue.Queue = queue.Queue(maxsize=500)
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def _worker(self) -> None:
        # BUG-X1 Fix: Sentinel-Wert (None-Tupel) ermöglicht sauberes Beenden.
        # Ohne Sentinel blockiert _action_queue.get() dauerhaft beim Prozessende.
        while True:
            item = self._action_queue.get()
            if item is None:   # Poison-Pill → Thread beenden
                self._action_queue.task_done()
                break
            action, ip, reason = item
            if action == "block":
                self._do_block(ip, reason)
            elif action == "unblock":
                self._do_unblock(ip)
            self._action_queue.task_done()

    def block_ip(self, ip: str, reason: str = "") -> None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self._fw_logger.warning("block_ip: Ungültige IP abgelehnt: %r", ip)
            return

        now = time.time()
        with self._lock:
            if ip in self.blocked_ips:
                return
            # Rate limiting
            last = self._block_timestamps.get(ip, 0)
            if now - last < self._rate_limit_seconds:
                return
            self._blocks_this_minute = [t for t in self._blocks_this_minute if now - t < 60]
            if len(self._blocks_this_minute) >= self._max_blocks_per_minute:
                self._fw_logger.warning("Rate-Limit: max Blocks/Minute erreicht, %s abgelehnt", ip)
                return
            self._block_timestamps[ip] = now
            self._blocks_this_minute.append(now)
            self.blocked_ips.add(ip)

        try:
            self._action_queue.put_nowait(("block", ip, reason))
        except queue.Full:
            self._fw_logger.warning("Firewall-Queue voll, Block für %s verworfen", ip)

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self.blocked_ips.discard(ip)
        try:
            self._action_queue.put_nowait(("unblock", ip, ""))
        except queue.Full:
            pass

    def stop(self) -> None:
        """Sendet Poison-Pill an den Worker-Thread und wartet auf sauberes Beenden."""
        try:
            self._action_queue.put(None, timeout=2)
        except queue.Full:
            pass
        self._worker_thread.join(timeout=5)

    def _do_block(self, ip: str, reason: str) -> None:
        if self.system == "Linux":
            ok = self._block_linux(ip)
        elif self.system == "Windows":
            ok = self._block_windows(ip)
        elif self.system == "Darwin":
            ok = self._block_macos(ip)
        else:
            ok = False
        if ok:
            self._fw_logger.warning("BLOCKED %s  Grund: %s", ip, reason or "–")
        else:
            self._fw_logger.error("Block fehlgeschlagen: %s", ip)

    def _do_unblock(self, ip: str) -> None:
        if self.system == "Linux":
            ok = self._unblock_linux(ip)
        elif self.system == "Windows":
            ok = self._unblock_windows(ip)
        elif self.system == "Darwin":
            ok = self._unblock_macos(ip)
        else:
            ok = False
        # Finding 3: Rückgabewert prüfen – "UNBLOCKED" nur loggen wenn erfolgreich.
        # Kein Fehler wenn IP nicht blockiert war (returncode != 0 bei iptables -D
        # ist normal wenn die Regel nicht existiert).
        if ok:
            self._fw_logger.info("UNBLOCKED %s", ip)
        else:
            self._fw_logger.debug("Unblock %s – Regel war nicht aktiv oder bereits entfernt.", ip)

    def cleanup_all(self) -> None:
        """Entfernt ALLE vom Tool gesetzten Firewall-Regeln (auch nach Absturz)."""
        # Zuerst Worker-Thread sauber beenden
        self.stop()
        with self._lock:
            ips = list(self.blocked_ips)
        for ip in ips:
            self._do_unblock(ip)
        # BUG-X3 Fix: iptables -D löscht nur die erste Übereinstimmung.
        # Nach einem Absturz + Neustart können doppelte Regeln entstehen.
        # While-Schleife wiederholt -D solange returncode == 0, bis alle weg sind.
        if self.system == "Linux":
            for cmd in ("iptables", "ip6tables"):
                try:
                    for chain in ("INPUT","OUTPUT","FORWARD"):
                        for _ in range(200):   # Sicherheitsschranke gegen Endlosschleife
                            r = subprocess.run(
                                [cmd, "-D", chain, "-m", "comment",
                                 "--comment", "NetFireMon", "-j", "DROP"],
                                capture_output=True
                            )
                            if r.returncode != 0:
                                break          # Keine Regel mehr vorhanden
                except Exception:
                    pass

    # ── Linux ──────────────────────────────────────────────────────────────
    @staticmethod
    def _is_ipv6(ip: str) -> bool:
        """Gibt True zurück wenn ip eine IPv6-Adresse ist."""
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def _block_linux(self, ip: str) -> bool:
        # BUG-A Fix: IPv6-Adressen brauchen ip6tables, nicht iptables.
        # Beide werden unabhängig aufgerufen – ein Fehler bei einem
        # Befehl verhindert nicht den anderen.
        cmd = "ip6tables" if self._is_ipv6(ip) else "iptables"
        ok = True
        for chain in ("INPUT","OUTPUT","FORWARD"):
            r = subprocess.run(
                [cmd, "-I", chain, "-s", ip,
                 "-m", "comment", "--comment", "NetFireMon", "-j", "DROP"],
                capture_output=True
            )
            ok = ok and r.returncode == 0
        return ok

    def _unblock_linux(self, ip: str) -> bool:
        # BUG-A Fix: ip6tables für IPv6-Adressen verwenden.
        cmd = "ip6tables" if self._is_ipv6(ip) else "iptables"
        any_ok = False
        for chain in ("INPUT","OUTPUT","FORWARD"):
            r = subprocess.run(
                [cmd, "-D", chain, "-s", ip,
                 "-m", "comment", "--comment", "NetFireMon", "-j", "DROP"],
                capture_output=True
            )
            if r.returncode == 0:
                any_ok = True
        return any_ok

    # ── Windows ────────────────────────────────────────────────────────────
    def _block_windows(self, ip: str) -> bool:
        name = f"NetFireMon_Block_{ip}"
        r = subprocess.run([
            "netsh","advfirewall","firewall","add","rule",
            f"name={name}","dir=in","action=block",
            f"remoteip={ip}","enable=yes"
        ], capture_output=True, text=True)
        return r.returncode == 0

    def _unblock_windows(self, ip: str) -> bool:
        name = f"NetFireMon_Block_{ip}"
        r = subprocess.run([
            "netsh","advfirewall","firewall","delete","rule",
            f"name={name}"
        ], capture_output=True, text=True)
        return r.returncode == 0
    # ── macOS ──────────────────────────────────────────────────────────────
    def _block_macos(self, ip: str) -> bool:
        try:
            r = subprocess.run(
                ["pfctl","-t","netfiremon_blocked","-T","add", ip],
                capture_output=True
            )
            return r.returncode == 0
        except Exception:
            return False

    def _unblock_macos(self, ip: str) -> bool:
        try:
            r = subprocess.run(
                ["pfctl","-t","netfiremon_blocked","-T","delete", ip],
                capture_output=True
            )
            return r.returncode == 0
        except Exception:
            return False


# ════════════════════════════════════════════════════════════════════════════
# EMAIL NOTIFIER
# ════════════════════════════════════════════════════════════════════════════

class EmailNotifier:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._logger = logging.getLogger("Email")
        self._queue: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def send(self, subject: str, body: str) -> None:
        if self.cfg.email_enabled:
            self._queue.put((subject, body))

    def stop(self) -> None:
        """Sendet Poison-Pill an den Worker-Thread."""
        try:
            self._queue.put(None, timeout=2)
        except Exception:
            pass
        self._thread.join(timeout=5)

    def _worker(self) -> None:
        # BUG-X1 Fix: Sentinel-Wert (None) ermöglicht sauberes Beenden des Threads.
        while True:
            item = self._queue.get()
            if item is None:   # Poison-Pill → Thread beenden
                break
            subject, body = item
            self._send_now(subject, body)

    def _send_now(self, subject: str, body: str) -> None:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[Net-Fire-Monitor] {subject}"
            msg["From"]    = self.cfg.email_sender or self.cfg.email_user
            msg["To"]      = self.cfg.email_recipient

            html_body = f"""<html><body style="font-family:monospace;background:#1a1a2e;color:#eee;padding:20px">
<h2 style="color:#e94560">🚨 Net-Fire-Monitor Alarm</h2>
<pre style="background:#16213e;padding:15px;border-radius:8px;color:#a8dadc;line-height:1.7">{body}</pre>
<hr style="border-color:#444">
<small style="color:#888">Net-Fire-Monitor v3.9</small>
</body></html>"""

            msg.attach(MIMEText(body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))

            with smtplib.SMTP(self.cfg.email_smtp, self.cfg.email_port, timeout=10) as s:
                s.ehlo(); s.starttls()
                s.login(self.cfg.email_user, self.cfg.email_password)
                s.sendmail(msg["From"], [msg["To"]], msg.as_string())
            self._logger.info("E-Mail gesendet: %s", subject)
        except Exception as e:
            self._logger.error("E-Mail fehlgeschlagen: %s", e)

    @staticmethod
    def test_connection(cfg: Config) -> tuple[bool, str]:
        import smtplib
        try:
            with smtplib.SMTP(cfg.email_smtp, cfg.email_port, timeout=5) as s:
                s.ehlo(); s.starttls()
                s.login(cfg.email_user, cfg.email_password)
            return True, "✅ Verbindung erfolgreich!"
        except Exception as e:
            return False, f"❌ Fehler: {e}"


# ════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE MANAGER
# ════════════════════════════════════════════════════════════════════════════

class ThreatIntelManager:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock = threading.Lock()
        self._bad_ips: set[str] = set()
        self._bad_cidrs: list   = []
        self._last_update: float = 0.0
        self._logger = logging.getLogger("ThreatIntel")
        self._cache_file = DATA_DIR / "threat_intel_cache.txt"
        self._stop_event = threading.Event()
        self._load_cache()
        if cfg.threat_intel_enabled:
            t = threading.Thread(target=self._update_loop, daemon=True)
            t.start()

    def stop(self) -> None:
        """Beendet den Update-Loop sauber (analog zu EmailNotifier/FirewallEngine)."""
        self._stop_event.set()

    def is_bad(self, ip: str) -> bool:
        with self._lock:
            if ip in self._bad_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
                return any(addr in net for net in self._bad_cidrs)
            except ValueError:
                return False

    def get_count(self) -> int:
        """Gibt die Anzahl der Einträge (IPs + CIDR-Netze) zurück."""
        with self._lock:
            return len(self._bad_ips) + len(self._bad_cidrs)

    def get_count_detail(self) -> tuple[int, int]:
        """Gibt (ip_count, cidr_count) zurück für detaillierte Anzeige."""
        with self._lock:
            return len(self._bad_ips), len(self._bad_cidrs)

    def _update_loop(self) -> None:
        import random
        # BUG-TI2 Fix: Zufälliger Start-Jitter (0–5 Min.) verhindert dass alle
        # Instanzen gleichzeitig dieselben Feed-Server treffen.
        jitter = random.randint(0, 300)
        self._stop_event.wait(timeout=jitter)
        while not self._stop_event.is_set():
            if time.time() - self._last_update >= self.cfg.threat_intel_update_interval:
                self._fetch_all_feeds()
            self._stop_event.wait(timeout=60)

    def _fetch_all_feeds(self) -> None:
        try:
            import requests as req
        except ImportError:
            return
        new_ips: set[str] = set()
        new_cidrs: list   = []
        # Max. Download-Größe pro Feed: 50 MB. Verhindert OOM wenn ein
        # kompromittierter Feed-Server eine riesige Datei sendet.
        _MAX_FEED_BYTES = 50 * 1024 * 1024

        for url in self.cfg.threat_intel_feeds:
            try:
                r = req.get(url, timeout=15, stream=True,
                            headers={"User-Agent": "NetFireMonitor/3.9"})
                if r.status_code != 200:
                    continue
                downloaded = 0
                lines_buf: list[str] = []
                for chunk in r.iter_content(chunk_size=65536, decode_unicode=True):
                    downloaded += len(chunk.encode("utf-8", errors="replace"))
                    if downloaded > _MAX_FEED_BYTES:
                        self._logger.warning(
                            "Feed %s überschreitet 50 MB – Download abgebrochen.", url
                        )
                        break
                    lines_buf.extend(chunk.splitlines())
                for line in lines_buf:
                    line = line.strip()
                    if not line or line.startswith(("#",";","//")):
                        continue
                    entry = line.split()[0].split(";")[0]
                    try:
                        if "/" in entry:
                            new_cidrs.append(ipaddress.ip_network(entry, strict=False))
                        else:
                            ipaddress.ip_address(entry)
                            new_ips.add(entry)
                    except ValueError:
                        continue
            except Exception as e:
                self._logger.warning("Feed-Fehler %s: %s", url, e)

        if new_ips or new_cidrs:
            with self._lock:
                self._bad_ips   = new_ips
                self._bad_cidrs = new_cidrs
                self._last_update = time.time()
            self._save_cache(new_ips, new_cidrs)
            self._logger.info("Threat Intel: %d IPs, %d CIDRs", len(new_ips), len(new_cidrs))

    def _save_cache(self, ips: set, cidrs: list | None = None) -> None:
        # INFO Fix: CIDRs werden ebenfalls in den Cache geschrieben.
        # Vorher gingen CIDR-Einträge nach jedem Neustart verloren
        # (bis zu 1h Lücke bis zum nächsten Feed-Update).
        try:
            lines = sorted(str(ip) for ip in ips)
            if cidrs:
                lines += sorted(str(net) for net in cidrs)
            self._cache_file.write_text("\n".join(lines), encoding="utf-8")
        except Exception:
            pass

    def _load_cache(self) -> None:
        if not self._cache_file.exists():
            return
        try:
            for line in self._cache_file.read_text().splitlines():
                line = line.strip()
                if not line: continue
                try:
                    if "/" in line:
                        self._bad_cidrs.append(ipaddress.ip_network(line, strict=False))
                    else:
                        self._bad_ips.add(line)
                except ValueError:
                    continue
            self._logger.info("ThreatIntel Cache: %d Einträge", len(self._bad_ips))
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# RULE ENGINE
# ════════════════════════════════════════════════════════════════════════════

class RuleEngine:
    def __init__(self, cfg: Config) -> None:
        self.rules: list[FirewallRule] = []
        for r in cfg.firewall_rules:
            if isinstance(r, dict):
                self.rules.append(FirewallRule(**{
                    k: v for k, v in r.items()
                    if k in FirewallRule.__dataclass_fields__
                }))

    def evaluate(self, src_ip: str, proto: str, dst_port) -> str | None:
        for rule in self.rules:
            if rule.proto != "any" and rule.proto.upper() != proto.upper():
                continue
            if rule.src_ip and rule.src_ip != src_ip:
                continue
            # BUG-05 Fix (v3.9): int()-Konvertierung absichern.
            # Scapy kann in Ausnahmefällen ungewöhnliche Port-Werte liefern.
            # ValueError hier würde die Paketverarbeitung stumm abbrechen.
            if rule.port:
                try:
                    port_int = int(dst_port or 0)
                except (ValueError, TypeError):
                    continue
                if rule.port != port_int:
                    continue
            return rule.action
        return None


# ════════════════════════════════════════════════════════════════════════════
# SYSLOG EXPORTER
# ════════════════════════════════════════════════════════════════════════════

class SyslogExporter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._logger = logging.getLogger("Syslog")
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def send_alert(self, message: str, severity: int = 4,
                   src_ip: str = "", reason: str = "") -> None:
        if not self.cfg.syslog_enabled:
            return
        try:
            self._queue.put_nowait((message, severity, src_ip, reason))
        except queue.Full:
            self._logger.warning("Syslog-Queue voll – Alarm verworfen")

    def stop(self) -> None:
        """Sendet Poison-Pill an den Worker-Thread (analog zu EmailNotifier/FirewallEngine).
        BUG-TI3 Fix: Ohne stop() blockierte der Thread dauerhaft beim Prozessende."""
        try:
            self._queue.put(None, timeout=2)
        except queue.Full:
            pass
        self._thread.join(timeout=5)

    def _worker(self) -> None:
        # BUG-TI3 Fix: Sentinel-Wert (None) ermöglicht sauberes Beenden des Threads.
        while True:
            item = self._queue.get()
            if item is None:   # Poison-Pill → Thread beenden
                self._queue.task_done()
                break
            msg, sev, src, reason = item
            try:
                self._send(msg, sev, src, reason)
            except Exception as e:
                self._logger.error("Syslog: %s", e)
            self._queue.task_done()

    def _send(self, message: str, severity: int, src_ip: str, reason: str) -> None:
        import socket as _sock
        priority = self.cfg.syslog_facility * 8 + severity
        ts = datetime.now().strftime("%b %d %H:%M:%S").replace("  "," ")
        try:
            hostname = _sock.gethostname()
        except Exception:
            hostname = "net-fire-monitor"
        cef_msg = (
            f"CEF:0|NetFireMonitor|Net-Fire-Monitor|3.9|{reason or 'ALERT'}|"
            f"{message}|{severity}|"
            f"{('src='+src_ip) if src_ip else ''} reason={reason or 'general'}"
        ).strip()
        data = f"<{priority}>{ts} {hostname} {self.cfg.syslog_tag}: {cef_msg}".encode("utf-8","replace")
        # Timeout auf beiden Protokollen verhindert blockierendes Warten
        # bei DNS-Problemen oder Netzwerkausfällen (Gemini-Audit Fix 4)
        if self.cfg.syslog_protocol.lower() == "tcp":
            with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((self.cfg.syslog_host, self.cfg.syslog_port))
                s.sendall(data + b"\n")
        else:
            with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as s:
                s.settimeout(2)   # UDP: kurzes Timeout – fire-and-forget
                s.sendto(data, (self.cfg.syslog_host, self.cfg.syslog_port))

    @staticmethod
    def test_connection(cfg: Config) -> tuple[bool, str]:
        import socket as _sock
        try:
            msg = b"<134>Net-Fire-Monitor: TEST OK"
            if cfg.syslog_protocol.lower() == "tcp":
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((cfg.syslog_host, cfg.syslog_port))
                    s.sendall(msg + b"\n")
            else:
                with _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM) as s:
                    s.sendto(msg, (cfg.syslog_host, cfg.syslog_port))
            return True, f"✅ Syslog OK ({cfg.syslog_protocol.upper()} → {cfg.syslog_host}:{cfg.syslog_port})"
        except Exception as e:
            return False, f"❌ Syslog-Fehler: {e}"


# ════════════════════════════════════════════════════════════════════════════
# SPEICHER-SICHERE DATENSTRUKTUREN  (Gemini-Audit Fix 2 + Fix 2b)
# Verhindern OOM und algorithmischen DoS bei SYN-Flood / IP-Spoofing
# ════════════════════════════════════════════════════════════════════════════

class _BoundedCounter:
    """
    Dict mit harter Obergrenze und O(1)-Verdrängung (FIFO via OrderedDict).

    WARUM OrderedDict statt min():
      Die alte min()-Implementierung hatte O(N) Komplexität beim Verdrängen.
      Bei 50.000 Einträgen und 10.000 Paketen/s → 500 Mio. Ops/s → 100% CPU.
      OrderedDict.popitem(last=False) ist O(1) – kein messbarer Overhead.
    """
    def __init__(self, maxsize: int = 50_000) -> None:
        from collections import OrderedDict as _OD
        self._data: _OD = _OD()
        self._maxsize = maxsize

    def increment(self, key, amount: int = 1) -> None:
        if key in self._data:
            self._data[key] += amount
            self._data.move_to_end(key)   # LRU: aktive IPs werden nicht verdrängt
        else:
            if len(self._data) >= self._maxsize:
                self._data.popitem(last=False)   # O(1): ältesten Eintrag entfernen
            self._data[key] = amount

    def get(self, key, default=0):
        return self._data.get(key, default)

    def items(self):
        return self._data.items()

    def __len__(self):
        return len(self._data)

    def clear(self):
        self._data.clear()

    def as_dict(self) -> dict:
        return dict(self._data)


class _BoundedPortscanTracker:
    """
    Portscan-Tracker mit harter Obergrenze für die Anzahl getrackter IPs.
    Wenn das Limit erreicht ist, wird der älteste Eintrag entfernt.

    BUG-D Fix: get_or_create() und clear_key() sind jetzt thread-safe.
    Der Processing-Worker ruft get_or_create() im eigenen Thread auf;
    ohne Lock könnten _data und _insertion_order inkonsistent werden.
    """
    def __init__(self, maxsize: int = 50_000) -> None:
        self._data: dict[str, deque] = {}
        self._maxsize = maxsize
        self._insertion_order: deque[str] = deque()
        self._lock = threading.Lock()

    def get_or_create(self, key: str) -> deque:
        with self._lock:
            if key not in self._data:
                if len(self._data) >= self._maxsize:
                    oldest = self._insertion_order.popleft()
                    self._data.pop(oldest, None)
                self._data[key] = deque(maxlen=200)
                self._insertion_order.append(key)
            return self._data[key]

    def clear_key(self, key: str) -> None:
        with self._lock:
            if key in self._data:
                self._data[key].clear()


# ════════════════════════════════════════════════════════════════════════════
# NETWORK MONITOR
# ════════════════════════════════════════════════════════════════════════════

class NetworkMonitor:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock              = threading.Lock()
        self.packet_count       = 0
        self.byte_count         = 0
        self.proto_counter:     dict[str, int] = defaultdict(int)
        self.ip_counter:        dict[str, int] = defaultdict(int)
        self.port_counter:      dict[int, int] = defaultdict(int)
        self.alert_count        = 0

        # SECURITY (Gemini-Audit Fix 2): Begrenzte Dicts verhindern OOM bei
        # SYN-Flood mit gespooften Source-IPs. Älteste Einträge werden verdrängt
        # sobald das Limit (max_tracked_ips) erreicht ist.
        _max = cfg.max_tracked_ips
        self._proto_total:    dict[str, int] = defaultdict(int)   # nur 4 Protokolle → kein Risiko
        self._ip_total:       _BoundedCounter = _BoundedCounter(_max)
        self._port_total:     dict[int, int]  = defaultdict(int)  # max 65535 Ports → OK
        self._portscan_track: _BoundedPortscanTracker = _BoundedPortscanTracker(_max)
        self.pps_history: deque[float] = deque(maxlen=60)
        self.bps_history: deque[float] = deque(maxlen=60)
        self.baseline_pps: float = 0.0
        self.baseline_bps: float = 0.0
        self.recent_packets: deque[PacketInfo] = deque(maxlen=50)
        self.alerts: deque[str] = deque(maxlen=100)
        self._pkt_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._stop_event = threading.Event()
        self._alert_cooldowns: dict[tuple, float] = {}
        self._alert_cooldown_secs: int = 300
        self._alert_cooldowns_last_cleanup: float = 0.0   # BUG-02 Fix (v3.9)
        self._muted_ips: dict[str, float] = {}
        self._muted_lock = threading.Lock()
        self._last_pps: float = 0.0
        self._last_bps: float = 0.0
        self._setup_logger()
        REPORT_DIR.mkdir(exist_ok=True)
        if cfg.report_rotate > 0:
            rotate_reports(cfg.report_rotate)
        self._report_path = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._csv_writer = None
        self._report_file = None
        if cfg.export_csv:
            self._open_csv()
        self._json_records: list[dict] = []

    def _setup_logger(self) -> None:
        from logging.handlers import RotatingFileHandler
        self.logger = logging.getLogger("NetMonitor")
        self.logger.setLevel(logging.DEBUG)
        fh = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(fh)

    def _open_csv(self) -> None:
        self._report_file = open(self._report_path, "w", newline="", encoding="utf-8")
        fields = ["timestamp","src_ip","dst_ip","protocol","src_port","dst_port","size","flags","ip_version"]
        self._csv_writer = csv.DictWriter(self._report_file, fieldnames=fields)
        self._csv_writer.writeheader()

    def _packet_callback(self, pkt) -> None:
        try:
            self._pkt_queue.put_nowait(pkt)
        except queue.Full:
            pass

    def _processing_worker(self) -> None:
        from scapy.all import IP, IPv6
        from scapy.layers.inet import TCP, UDP, ICMP
        while not self._stop_event.is_set():
            try:
                pkt = self._pkt_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._process_packet(pkt)

    def _process_packet(self, pkt) -> None:
        from scapy.all import IP, IPv6
        from scapy.layers.inet import TCP, UDP, ICMP
        if IP in pkt:
            layer, ipver = pkt[IP], 4
        elif IPv6 in pkt:
            layer, ipver = pkt[IPv6], 6
        else:
            return

        src_ip = layer.src
        dst_ip = layer.dst

        if self.cfg.blacklist and src_ip in self.cfg.blacklist:
            self._fire_alert(f"⛔  Blacklist-IP: {src_ip}", src_ip=src_ip, reason="blacklist")

        if _threat_intel and _threat_intel.is_bad(src_ip):
            self._fire_alert(f"☠️  Bekannte Bedrohung: {src_ip}", src_ip=src_ip, reason="threat_intel")
            # BUG-TI1 Fix: Whitelist und private IPs vor auto_block prüfen.
            # Vorher konnte eine whitelisted IP blockiert werden wenn sie zufällig
            # in einem TI-Feed auftauchte. _firewall.block_ip() im IPC-Pfad prüft
            # die Whitelist, aber dieser direkte Aufruf tat es nicht.
            if (self.cfg.threat_intel_auto_block and _firewall
                    and src_ip not in self.cfg.whitelist
                    and not is_private_ip(src_ip)):
                _firewall.block_ip(src_ip, reason="Threat Intel")

        proto = flags = ""
        src_port = dst_port = ""
        if TCP in pkt:
            proto, src_port, dst_port = "TCP", pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto, src_port, dst_port = "UDP", pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            proto = "OTHER"

        size = len(pkt)

        if _rule_engine and dst_port:
            action = _rule_engine.evaluate(src_ip, proto, dst_port)
            if action == "block":
                self._fire_alert(f"🚫  Regel-Block: {src_ip} → {proto}/{dst_port}",
                                 src_ip=src_ip, reason=f"rule:{proto}/{dst_port}")
                if _firewall:
                    _firewall.block_ip(src_ip, reason=f"Regel {proto}/{dst_port}")
                return
            elif action == "alert":
                self._fire_alert(f"⚠️   Regel-Alarm: {src_ip} → {proto}/{dst_port}",
                                 src_ip=src_ip, reason=f"rule_alert:{proto}/{dst_port}")

        with self._lock:
            self.packet_count += 1
            self.byte_count   += size
            self.proto_counter[proto] += 1
            self.ip_counter[src_ip]  += 1
            self._proto_total[proto] += 1
            self._ip_total.increment(src_ip)       # bounded – verhindert OOM
            if dst_port:
                self.port_counter[int(dst_port)] += 1
                self._port_total[int(dst_port)]  += 1

        if self.cfg.detect_portscan and proto in ("TCP","UDP") and dst_port:
            self._check_portscan(src_ip, int(dst_port))

        info = PacketInfo(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            src_ip=src_ip, dst_ip=dst_ip, protocol=proto,
            src_port=src_port, dst_port=dst_port,
            size=size, flags=flags, ip_version=ipver,
        )
        with self._lock:
            self.recent_packets.append(info)

        if self._csv_writer:
            try:
                self._csv_writer.writerow(asdict(info))
                self._report_file.flush()
            except Exception:
                pass

    def _check_portscan(self, src_ip: str, dst_port: int) -> None:
        now = time.time()
        track = self._portscan_track.get_or_create(src_ip)  # bounded – verhindert OOM
        track.append((now, dst_port))
        recent = [(t, p) for t, p in track if now - t <= 10]
        unique = len({p for _, p in recent})
        if unique >= self.cfg.portscan_limit:
            self._fire_alert(f"🔍  Port-Scan von {src_ip} ({unique} Ports/10s)",
                             src_ip=src_ip, reason="portscan")
            self._portscan_track.clear_key(src_ip)

    def _is_throttled(self, src_ip: str, reason: str) -> bool:
        now = time.time()
        with self._muted_lock:
            exp = self._muted_ips.get(src_ip, 0)
            if exp == -1 or now < exp:
                return True
            elif exp != 0 and now >= exp:
                del self._muted_ips[src_ip]
        key = (src_ip, reason)
        with self._lock:
            # BUG-02 Fix (v3.9): Periodisches Cleanup alter Cooldown-Einträge.
            # Ohne Cleanup wächst das Dict unbegrenzt – jede je gesehene IP bleibt drin.
            # Cleanup alle 10 Minuten: Einträge die älter als 2× cooldown_secs sind entfernen.
            if now - self._alert_cooldowns_last_cleanup > 600:
                cutoff = now - self._alert_cooldown_secs * 2
                expired = [k for k, t in self._alert_cooldowns.items() if t < cutoff]
                for k in expired:
                    del self._alert_cooldowns[k]
                self._alert_cooldowns_last_cleanup = now

            last = self._alert_cooldowns.get(key, 0.0)
            if last == 0.0:
                self._alert_cooldowns[key] = now
                return False
            if now - last < self._alert_cooldown_secs:
                return True
            self._alert_cooldowns[key] = now
            return False

    def mute_ip(self, ip: str, duration_secs: int = 3600) -> None:
        with self._muted_lock:
            self._muted_ips[ip] = -1 if duration_secs == -1 else time.time() + duration_secs
        with self._lock:
            for k in [k for k in self._alert_cooldowns if k[0] == ip]:
                del self._alert_cooldowns[k]

    def unmute_ip(self, ip: str) -> None:
        with self._muted_lock:
            self._muted_ips.pop(ip, None)
        with self._lock:
            for k in [k for k in self._alert_cooldowns if k[0] == ip]:
                del self._alert_cooldowns[k]

    def get_muted_ips(self) -> dict[str, float]:
        now = time.time()
        with self._muted_lock:
            for ip in [ip for ip, e in self._muted_ips.items() if e != -1 and now >= e]:
                del self._muted_ips[ip]
            return dict(self._muted_ips)

    def _fire_alert(self, message: str, level: str = "WARNING",
                    src_ip: str = "", reason: str = "") -> None:
        if src_ip and self._is_throttled(src_ip, reason):
            return
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {message}"
        with self._lock:
            self.alerts.appendleft(entry)
            self.alert_count += 1
        if self.cfg.notify_log:
            getattr(self.logger, level.lower(), self.logger.warning)(message)
        if self.cfg.notify_desktop:
            threading.Thread(target=send_notification,
                             args=("Net-Fire-Monitor", message), daemon=True).start()

        if _email and src_ip:
            info = enrich_ip(src_ip)
            threat_marker = ("☠️  JA – in Threat-Intel-Liste!"
                             if info["threat_intel"] else "✅ Nicht bekannt")
            blocked_line = (f"Aktion    : IP blockiert 🚫\n"
                            if _firewall and src_ip in _firewall.blocked_ips else "")
            body = (
                f"Zeitpunkt : {ts}\n"
                f"Alarm     : {message}\n\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"IP        : {src_ip}\n"
                f"Hostname  : {info['hostname']}\n"
                f"Geo-IP    : {info['geo']}\n"
                f"Besitzer  : {info['org']}\n"
                f"Bedrohung : {threat_marker}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"Grund     : {reason or '–'}\n"
                f"Modus     : {self.cfg.firewall_mode}\n"
                f"{blocked_line}"
            )
            _email.send(subject=message[:60], body=body)

        if _syslog:
            _syslog.send_alert(message, severity=4, src_ip=src_ip, reason=reason)

        if src_ip and _firewall and self.cfg.firewall_mode == "auto":
            if src_ip not in self.cfg.whitelist and not is_private_ip(src_ip):
                _firewall.block_ip(src_ip, reason=reason or message)

    def _evaluate_interval(self, elapsed: float) -> tuple[float, float, str]:
        with self._lock:
            pkts   = self.packet_count
            bytes_ = self.byte_count
            top_ip = max(self.ip_counter, key=self.ip_counter.get) if self.ip_counter else "Unknown"
            self.packet_count = 0
            self.byte_count   = 0
            self.proto_counter.clear()
            self.ip_counter.clear()
            self.port_counter.clear()
        pps = round(pkts  / elapsed, 2) if elapsed > 0 else 0.0
        bps = round(bytes_ / elapsed, 2) if elapsed > 0 else 0.0
        self.pps_history.append(pps)
        self.bps_history.append(bps)
        return pps, bps, top_ip

    def _get_iface(self):
        if self.cfg.interfaces:
            return self.cfg.interfaces
        return self.cfg.interface or None

    def measure_baseline(self, use_saved: bool = True) -> bool:
        """
        Misst die Baseline oder lädt sie aus dem Snapshot.

        Wenn use_saved=True und eine gültige Baseline vorhanden ist
        (nicht älter als BASELINE_MAX_AGE_SECS / 24h), wird diese direkt
        geladen – keine Wartezeit nach Stromausfall / Neustart.

        Gibt True zurück wenn aus Snapshot geladen, False wenn frisch gemessen.
        """
        from scapy.all import sniff

        if use_saved:
            saved = load_baseline()
            if saved is not None:
                self.baseline_pps, self.baseline_bps = saved
                self.logger.info(
                    "Baseline aus Snapshot: %.2f pps | %.0f B/s",
                    self.baseline_pps, self.baseline_bps
                )
                return True

        # Frisch messen
        self.logger.info("Baseline-Messung (%ds) …", self.cfg.average_period)
        self._stop_event.clear()
        worker = threading.Thread(target=self._processing_worker, daemon=True)
        worker.start()
        t0 = time.time()
        sniff(filter=self.cfg.bpf_filter, iface=self._get_iface(),
              prn=self._packet_callback, store=False, timeout=self.cfg.average_period)
        time.sleep(0.5)
        elapsed = time.time() - t0
        pps, bps, _ = self._evaluate_interval(elapsed)
        self.baseline_pps = pps
        self.baseline_bps = bps
        self._stop_event.set()
        worker.join(timeout=3)
        self._stop_event.clear()
        self.logger.info("Baseline gemessen: %.2f pps | %.0f B/s", pps, bps)
        save_baseline(self)
        return False

    # Interval für Live-State-Export (Sekunden) und Baseline-Speicherung
    _LIVE_STATE_INTERVAL  = LIVE_STATE_INTERVAL   # 2s
    _BASELINE_SAVE_INTERVAL = 600                  # 10 Min.

    def run_monitor_loop(self) -> None:
        from scapy.all import sniff
        self._stop_event.clear()
        worker = threading.Thread(target=self._processing_worker, daemon=True)
        worker.start()

        last_live_save    = 0.0
        last_baseline_save = time.time()

        try:
            while True:
                t0 = time.time()
                sniff(filter=self.cfg.bpf_filter, iface=self._get_iface(),
                      prn=self._packet_callback, store=False,
                      timeout=self.cfg.monitor_interval)
                elapsed = time.time() - t0
                pps, bps, top_ip = self._evaluate_interval(elapsed)
                self._last_pps = pps
                self._last_bps = bps

                # Schwellenwert-Alarm
                limit_pps = self.baseline_pps * (1 + self.cfg.threshold / 100)
                limit_bps = self.baseline_bps * (1 + self.cfg.threshold / 100)
                if pps > limit_pps or bps > limit_bps:
                    if top_ip not in self.cfg.whitelist:
                        self._fire_alert(
                            f"Traffic {pps:.1f} pps via {top_ip} "
                            f"(Schwellenwert: {limit_pps:.1f} pps / +{self.cfg.threshold}%)",
                            src_ip=top_ip, reason="PPS_Exceeded"
                        )

                now = time.time()

                # ── IPC: Live-State alle 2s exportieren (für Web-Prozess) ─────
                if now - last_live_save >= self._LIVE_STATE_INTERVAL:
                    save_live_state(self)
                    last_live_save = now

                # ── IPC: Kommandos vom Web-Prozess verarbeiten ────────────────
                self._process_ipc_commands()

                # ── Baseline + Persistenz alle 10 Min. speichern ──────────────
                if now - last_baseline_save >= self._BASELINE_SAVE_INTERVAL:
                    save_baseline(self)
                    save_persist()
                    last_baseline_save = now

        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            worker.join(timeout=3)
            self._close_reports()

    def _process_ipc_commands(self) -> None:
        """
        Liest und verarbeitet alle Kommandos aus CMD_QUEUE_DIR.
        Läuft im Monitor-Prozess (als root) → darf iptables aufrufen.
        """
        commands = CommandQueue.pop_all()
        if not commands:
            return

        cfg = self.cfg

        for cmd in commands:
            action = cmd.get("action", "")
            ip     = cmd.get("ip", "").strip()

            try:
                # ── Firewall-Aktionen ─────────────────────────────────────
                if action == "block" and ip:
                    if validate_ip(ip) and not is_private_ip(ip) and ip not in cfg.whitelist:
                        if _firewall:
                            _firewall.block_ip(ip, reason="Web-Interface (IPC)")
                        self.logger.info("IPC block: %s", ip)

                elif action == "unblock" and ip:
                    if validate_ip(ip) and _firewall:
                        _firewall.unblock_ip(ip)
                        self.logger.info("IPC unblock: %s", ip)

                # ── Stummschaltung ────────────────────────────────────────
                elif action == "mute" and ip:
                    if validate_ip(ip):
                        duration = int(cmd.get("duration", 3600))
                        self.mute_ip(ip, duration_secs=duration)

                elif action == "unmute" and ip:
                    if validate_ip(ip):
                        self.unmute_ip(ip)

                # ── Cooldown ──────────────────────────────────────────────
                elif action == "set_cooldown":
                    secs = int(cmd.get("seconds", 300))
                    if 0 <= secs <= 86400:
                        self._alert_cooldown_secs = secs

                # ── Config-Reload (Gemini-Audit Fix 3) ───────────────────
                # Web-Prozess schreibt cfg.save() + push("reload_config").
                # Monitor lädt Config neu → kein Split-Brain mehr.
                elif action == "reload_config":
                    new_cfg = Config.load()
                    self.cfg = new_cfg
                    cfg = new_cfg
                    # Alle abhängigen Engines neu starten
                    global _rule_engine, _email, _syslog, _threat_intel
                    _rule_engine = RuleEngine(new_cfg)
                    if new_cfg.email_enabled:
                        if _email is None:
                            _email = EmailNotifier(new_cfg)
                        else:
                            _email.cfg = new_cfg
                    else:
                        if _email:
                            _email.stop()
                        _email = None
                    # SyslogExporter: stop() vor Neustart damit kein Zombie-Thread bleibt
                    if new_cfg.syslog_enabled:
                        if _syslog is None:
                            _syslog = SyslogExporter(new_cfg)
                        else:
                            _syslog.cfg = new_cfg
                    else:
                        if _syslog:
                            _syslog.stop()
                        _syslog = None
                    # ThreatIntelManager: bei Feeds-Änderung neu laden
                    if new_cfg.threat_intel_enabled:
                        if _threat_intel is None:
                            _threat_intel = ThreatIntelManager(new_cfg)
                        else:
                            _threat_intel.cfg = new_cfg
                    else:
                        if _threat_intel:
                            _threat_intel.stop()
                        _threat_intel = None
                    self.logger.info("IPC reload_config: Config neu geladen.")

                # ── Whitelist / Blacklist ─────────────────────────────────
                # Werden jetzt NUR über reload_config synchronisiert:
                # Web schreibt Config → push(reload_config) → Monitor lädt neu.
                # Direktes In-Memory-Mutieren entfällt (war fehleranfällig).

                else:
                    self.logger.debug("IPC: Unbekannte Aktion '%s' ignoriert", action)

            except Exception as e:
                self.logger.warning("IPC-Kommando '%s' fehlgeschlagen: %s", action, e)

    def _close_reports(self) -> None:
        if self._report_file and not self._report_file.closed:
            self._report_file.close()
        if self.cfg.export_json and self._json_records:
            jp = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            jp.write_text(json.dumps(self._json_records, indent=2, ensure_ascii=False))

    def get_top_talkers(self, n: int = 8) -> list:
        with self._lock:
            return sorted(self._ip_total.as_dict().items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_ports(self, n: int = 8) -> list:
        with self._lock:
            return sorted(self._port_total.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_proto_stats(self) -> dict:
        with self._lock:
            return dict(self._proto_total)
