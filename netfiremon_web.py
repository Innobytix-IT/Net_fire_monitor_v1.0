"""
╔══════════════════════════════════════════════════════════════╗
║     NET-FIRE-MONITOR  v3.9  –  Web-Modus                    ║
║     Flask + Gunicorn · HTTPS · CSRF-Schutz                  ║
╚══════════════════════════════════════════════════════════════╝

Verwendung:
  sudo python netfiremon_web.py              # Interaktiv
  sudo python netfiremon_web.py --auto       # Für systemd
  sudo python netfiremon_web.py --setup      # Setup erzwingen
"""

from __future__ import annotations
import json, os, platform, sys, time, threading, secrets
from pathlib import Path
from dataclasses import asdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from core import (
    SETUP_DONE_FILE, first_run_setup,
    Config, CONFIG_FILE, LOG_FILE, FIREWALL_LOG, STATE_FILE, GEOIP_DB,
    DATA_DIR,
    FirewallEngine, EmailNotifier, ThreatIntelManager, RuleEngine, SyslogExporter,
    NetworkMonitor,
    save_state, load_state,
    restore_on_startup,
    save_live_state, read_live_state, CommandQueue,
    _fmt_bps, validate_ip, is_private_ip, resolve_hostname, geo_lookup,
    _hash_password, _verify_password, _setup_web_password,
    KNOWN_SERVICES, PLYER_OK,
)
import core as _core

if not SETUP_DONE_FILE.exists():
    first_run_setup()
    if platform.system() == "Windows":
        import subprocess as _sp; sys.exit(_sp.call([sys.executable] + sys.argv))
    else:
        os.execv(sys.executable, [sys.executable] + sys.argv)

try:
    from scapy.all import sniff, IP, IPv6
    from scapy.layers.inet import TCP, UDP, ICMP
except ImportError:
    sys.exit("❌  Scapy nicht gefunden.")

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.rule import Rule
except ImportError:
    sys.exit("❌  Rich nicht gefunden.")

console = Console()
_mon_ref: NetworkMonitor | None = None

def _is_single_process() -> bool:
    """
    Erkennt ob Web und Monitor im selben Prozess laufen (Windows / manueller Start).
    Wenn True → direkte Ausführung statt IPC-Queue.
    Wenn False → IPC-Queue (Linux Zwei-Prozess-Modus via systemd).
    """
    return _mon_ref is not None

# ════════════════════════════════════════════════════════════════════════════
# HTTPS / TLS – Self-Signed-Zertifikat generieren
# ════════════════════════════════════════════════════════════════════════════

def _ensure_tls_cert(cert_dir: Path) -> tuple[Path, Path]:
    """
    Gibt (cert.pem, key.pem) zurück.
    Erzeugt Self-Signed-Zertifikat wenn noch nicht vorhanden.
    SCHWACHSTELLE-S3 Fix: Alle lokalen Host-IPs werden automatisch als SAN
    eingetragen, damit der Browser bei Zugriff über LAN-IP keine Warnung zeigt.
    """
    cert_dir.mkdir(exist_ok=True)
    cert = cert_dir / "cert.pem"
    key  = cert_dir / "key.pem"
    if cert.exists() and key.exists():
        return cert, key

    console.print("[cyan]🔐  Generiere Self-Signed TLS-Zertifikat …[/cyan]")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as _dt
        import ipaddress as _ip

        # ── S3 Fix: alle lokalen IPs des Hosts ermitteln ──────────────────
        def _local_ips() -> list:
            """Sammelt alle nicht-Loopback IPv4/IPv6-Adressen des Hosts."""
            ips = []
            try:
                import socket as _sock
                hostname = _sock.gethostname()
                for info in _sock.getaddrinfo(hostname, None):
                    addr = info[4][0]
                    try:
                        parsed = _ip.ip_address(addr)
                        if not parsed.is_loopback:
                            ips.append(parsed)
                    except ValueError:
                        pass
            except Exception:
                pass
            return ips

        san_entries = [
            x509.DNSName("localhost"),
            x509.IPAddress(_ip.IPv4Address("127.0.0.1")),
            x509.IPAddress(_ip.IPv6Address("::1")),
        ]
        for host_ip in _local_ips():
            san_entries.append(x509.IPAddress(host_ip))
            console.print(f"[dim]   SAN: {host_ip}[/dim]")

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Net-Fire-Monitor"),
            x509.NameAttribute(NameOID.COMMON_NAME, "net-fire-monitor.local"),
        ])
        now_utc = _dt.datetime.now(_dt.timezone.utc)
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now_utc)
            .not_valid_after(now_utc + _dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .sign(priv, hashes.SHA256())
        )
        key.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        cert.write_bytes(cert_obj.public_bytes(serialization.Encoding.PEM))
        if platform.system() != "Windows":
            key.chmod(0o600)
        console.print("[green]✅  TLS-Zertifikat erstellt (inkl. LAN-IP SANs).[/green]")
        return cert, key

    except ImportError:
        try:
            import subprocess
            # openssl-Fallback: ohne automatische IP-Erkennung (openssl req
            # unterstützt keine einfache SAN-Übergabe per -subj)
            subprocess.run([
                "openssl","req","-x509","-newkey","rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days","3650","-nodes",
                "-subj","/C=DE/O=NetFireMonitor/CN=net-fire-monitor.local",
            ], capture_output=True, check=True)
            if platform.system() != "Windows":
                key.chmod(0o600)
            console.print("[green]✅  TLS-Zertifikat (openssl) erstellt.[/green]")
            console.print("[yellow]   Hinweis: Für LAN-IP-SANs bitte 'cryptography' installieren.[/yellow]")
            return cert, key
        except Exception as e:
            console.print(f"[yellow]⚠️  TLS-Zertifikat konnte nicht erstellt werden: {e}[/yellow]")
            console.print("[yellow]   Web-Interface läuft ohne HTTPS (HTTP only).[/yellow]")
            return Path(""), Path("")


# ════════════════════════════════════════════════════════════════════════════
# FLASK-WEBAPP  (mit CSRF-Schutz)
# ════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).parent


def _build_flask_app(network_mode: bool, password_hash: str):
    """Erstellt und konfiguriert die Flask-App. Wird von start_web aufgerufen."""
    try:
        from flask import (Flask, jsonify, redirect, render_template,
                           request, session, url_for, abort)
        from functools import wraps
    except ImportError:
        console.print("[red]Flask nicht installiert. pip install flask[/red]")
        sys.exit(1)

    WEB_DIR = SCRIPT_DIR / "web"
    app = Flask(
        "net_fire_monitor",
        root_path       = str(SCRIPT_DIR),
        template_folder = str(WEB_DIR / "templates"),
        static_folder   = str(WEB_DIR / "static"),
        static_url_path = "/static",
    )

    # ── Secret Key (persistent) ────────────────────────────────────────────
    _sk_file = DATA_DIR / ".web_secret_key"
    if _sk_file.exists():
        try:
            app.secret_key = _sk_file.read_text(encoding="utf-8").strip()
        except Exception:
            app.secret_key = secrets.token_hex(32)
    else:
        app.secret_key = secrets.token_hex(32)
        try:
            _sk_file.write_text(app.secret_key, encoding="utf-8")
            if platform.system() != "Windows":
                _sk_file.chmod(0o600)
        except Exception:
            pass

    app.config.update(
        # SCHWACHSTELLE-S2 Fix: __Host- Präfix verhindert Cookie-Hijacking durch
        # Subdomains. Der Browser akzeptiert diesen Cookie nur über HTTPS und
        # exakt den gesetzten Host – kein Überschreiben durch Subdomains möglich.
        # Hinweis: __Host- erfordert SESSION_COOKIE_SECURE=True und path="/".
        SESSION_COOKIE_NAME     = "__Host-nfm_session" if network_mode else "nfm_session",
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",
        SESSION_COOKIE_SECURE   = network_mode,
        SESSION_COOKIE_PATH     = "/",
        PERMANENT_SESSION_LIFETIME = 28800,  # 8 Stunden
    )

    # SECURITY (Gemini-Audit Fix 1): ProxyFix NUR wenn explizit ein
    # Reverse-Proxy konfiguriert ist. Sonst ist X-Forwarded-For fälschbar.
    _cfg_proxy = Config.load()
    if _cfg_proxy.behind_reverse_proxy:
        try:
            from werkzeug.middleware.proxy_fix import ProxyFix
            app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        except ImportError:
            pass

    # Sicherheits-Assertion
    if network_mode and not password_hash:
        raise RuntimeError("Netzwerkmodus ohne Passwort ist nicht erlaubt!")

    # ── CSRF-Schutz ────────────────────────────────────────────────────────
    def _csrf_token() -> str:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    def _csrf_required(f):
        """Decorator: prüft CSRF-Token bei POST/PUT/DELETE-Requests."""
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method in ("POST","PUT","DELETE","PATCH"):
                # JSON-APIs: Token im Header X-CSRF-Token
                # Form-Posts: Token im Formularfeld csrf_token
                token = (request.headers.get("X-CSRF-Token")
                         or request.form.get("csrf_token",""))
                if not token or not hmac_compare(token, session.get("csrf_token","")):
                    abort(403)
            return f(*args, **kwargs)
        return wrapped

    def hmac_compare(a: str, b: str) -> bool:
        import hmac as _hmac
        return _hmac.compare_digest(a.encode(), b.encode())

    # ── Auth ───────────────────────────────────────────────────────────────
    def auth_req(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if network_mode and not session.get("authenticated"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped

    # ── Brute-Force-Schutz ─────────────────────────────────────────────────
    _login_attempts: dict[str, list] = {}
    _LOCKOUT_ATTEMPTS = 10
    _LOCKOUT_DURATION = 900
    # BUG-03 Fix (v3.9): Maximale Dict-Größe begrenzen.
    # Ohne Limit wächst das Dict bei DDoS-artigen Login-Angriffen von tausenden
    # IPs unbegrenzt. FIFO-Verdrängung entfernt den ältesten Eintrag wenn voll.
    _LOGIN_ATTEMPTS_MAXSIZE = 10_000
    # BUG-X4 Fix: Lock schützt _login_attempts gegen parallele Schreibzugriffe
    # bei mehreren gleichzeitigen Login-Requests (Gunicorn / Gevent-Modus).
    _login_lock = threading.Lock()

    def _is_locked_out(ip: str) -> bool:
        now = time.time()
        with _login_lock:
            attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOCKOUT_DURATION]
            _login_attempts[ip] = attempts
            return len(attempts) >= _LOCKOUT_ATTEMPTS

    def _record_failed(ip: str) -> None:
        # BUG-03 Fix (v3.9): Ältesten Eintrag verdrängen wenn Limit erreicht
        with _login_lock:
            if len(_login_attempts) >= _LOGIN_ATTEMPTS_MAXSIZE and ip not in _login_attempts:
                try:
                    oldest_ip = next(iter(_login_attempts))
                    del _login_attempts[oldest_ip]
                except (StopIteration, RuntimeError):
                    pass
            attempts = _login_attempts.get(ip, [])
            attempts.append(time.time())
            _login_attempts[ip] = attempts

    # ── Security-Header ────────────────────────────────────────────────────
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=()"
        # HINWEIS S1: 'unsafe-inline' in script-src ist hier bewusst belassen.
        # Das Dashboard nutzt zahlreiche onclick=/oninput=-Inline-Event-Handler in
        # base.html und dashboard.html. CSP-Nonces gelten NUR für <script nonce=...>
        # Blöcke – Inline-Event-Handler (onclick=) lassen sich nicht per Nonce
        # absichern; dafür wäre ein vollständiges Refactoring aller Templates auf
        # addEventListener() erforderlich (zukünftige Verbesserung, TODO).
        # Der wesentliche XSS-Schutz erfolgt stattdessen durch:
        #   - CSRF-Token auf allen schreibenden Requests
        #   - Konsequentes escHtml() für alle Server-Daten im Frontend-JS
        #   - X-Frame-Options: DENY  (verhindert Clickjacking)
        #   - SameSite=Lax Session-Cookie
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        if network_mode:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ── Template-Kontext: CSRF-Token überall verfügbar ────────────────────
    @app.context_processor
    def inject_globals():
        return {"csrf_token": _csrf_token()}

    # ── Login ──────────────────────────────────────────────────────────────
    @app.route("/login", methods=["GET","POST"])
    def login():
        client_ip = request.remote_addr or "unknown"
        if request.method == "POST":
            if _is_locked_out(client_ip):
                return render_template("login.html",
                    error="Zu viele Fehlversuche. Bitte 15 Minuten warten.")
            pw = request.form.get("password","")
            if _verify_password(pw, password_hash):
                session["authenticated"] = True
                session.permanent = True
                _login_attempts.pop(client_ip, None)
                # Hash-Migration auf scrypt
                if not password_hash.startswith("scrypt:"):
                    try:
                        new_hash = _hash_password(pw)
                        wc = DATA_DIR / "net_fire_monitor_web_config.json"
                        wc.write_text(json.dumps({"password_hash": new_hash}, indent=2))
                        if platform.system() != "Windows":
                            wc.chmod(0o600)
                    except Exception:
                        pass
                return redirect(url_for("index"))
            _record_failed(client_ip)
            remaining = max(0, _LOCKOUT_ATTEMPTS - len(_login_attempts.get(client_ip, [])))
            return render_template("login.html",
                error=f"Falsches Passwort! ({remaining} Versuch(e) verbleibend)")
        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ── Dashboard ──────────────────────────────────────────────────────────
    @app.route("/")
    @auth_req
    def index():
        return render_template("dashboard.html", network_mode=network_mode)

    # ── API: Status ────────────────────────────────────────────────────────
    @app.route("/api/status")
    @auth_req
    def api_status():
        """
        IPC-Version: Liest Live-Daten aus LIVE_STATE_FILE (Gemini-Audit Fix 1).
        Der Monitor-Prozess schreibt diese Datei alle 2s.
        Fallback auf STATE_FILE wenn kein Live-State vorhanden
        (Monitor läuft nicht / frisch gestartet).
        """
        # 1. Live-State vom Monitor-Prozess lesen
        live = read_live_state()
        if live:
            # Key-Normalisierung: save_live_state schreibt "proto_counts",
            # das Dashboard-JS erwartet "protos"
            if "proto_counts" in live and "protos" not in live:
                live["protos"] = live.pop("proto_counts")
            return jsonify(live)

        # 2. Fallback: letzter gespeicherter Snapshot (beim Start / Monitor gestoppt)
        cfg   = Config.load()
        state = load_state()
        snap_info = None
        if state:
            snap_info = {
                "saved_by": state.get("saved_by", "terminal"),
                "saved_at": state.get("saved_at", "")[:19].replace("T", " "),
            }
        return jsonify({
            "firewall_mode":  cfg.firewall_mode,
            "interface":      cfg.interface or "alle",
            "threshold":      cfg.threshold,
            "baseline_pps":   state.get("baseline_pps", 0),
            "baseline_bps":   state.get("baseline_bps", 0),
            "alert_count":    state.get("alert_count", 0),
            "ti_count":       0,
            "blocked_count":  len(state.get("blocked_ips", [])),
            "blocked_ips":    state.get("blocked_ips", []),
            "pps": 0, "bps": 0,
            "protos":         state.get("proto_counts", {}),
            "top_talkers":    state.get("top_talkers", []),
            "top_ports":      state.get("top_ports", []),
            "recent_packets": state.get("recent_packets", []),
            "recent_alerts":  state.get("recent_alerts", []),
            "geo_db_missing": not GEOIP_DB.exists(),
            "snapshot_info":  snap_info,
            "monitor_offline": True,   # Signal ans Dashboard: Monitor läuft nicht
        })

    # ── API: Alarme ────────────────────────────────────────────────────────
    @app.route("/api/alarms")
    @auth_req
    def api_alarms():
        """Liest Alarme aus Live-State (Monitor läuft) oder Log-Datei (Fallback)."""
        alarms = []

        # 1. Live-Alarme aus IPC-State
        live = read_live_state()
        if live:
            for entry in live.get("recent_alerts", []):
                ts  = entry[:23] if len(entry) > 23 else ""
                msg = entry.split("] ")[-1] if "]" in entry else entry
                ip  = next((p.strip(".,:()")
                            for p in msg.split()
                            if validate_ip(p.strip(".,:()"))), "")
                alarms.append({"ts": ts, "msg": msg, "ip": ip})

        # 2. Fallback: Log-Datei
        if not alarms and LOG_FILE.exists():
            lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in reversed(lines[-500:]):
                if "WARNING" not in line and "ERROR" not in line:
                    continue
                ts  = line[:23] if len(line) > 23 else ""
                msg = line.split("] ")[-1] if "]" in line else line
                ip  = next((p.strip(".,:()")
                            for p in msg.split()
                            if validate_ip(p.strip(".,:()"))), "")
                alarms.append({"ts": ts, "msg": msg, "ip": ip})
                if len(alarms) >= 200:
                    break

        return jsonify({"alarms": alarms[:200]})

    # ── API: Firewall-Aktion ───────────────────────────────────────────────
    @app.route("/api/firewall-action", methods=["POST"])
    @auth_req
    @_csrf_required
    def api_firewall_action():
        """
        Hybrid: direkter Aufruf wenn Monitor im selben Prozess (Windows),
        sonst IPC-Queue (Linux Zwei-Prozess-Modus).
        """
        data   = request.get_json() or {}
        action = data.get("action","")
        ip     = data.get("ip","").strip()

        if action in ("block","unblock") and ip:
            if not validate_ip(ip):
                return jsonify({"ok":False,"message":"Ungültige IP-Adresse"})
            if _is_single_process():
                fw = _core._firewall
                if not fw:
                    return jsonify({"ok":False,"message":"Firewall-Engine nicht initialisiert"})
                if action == "block":
                    fw.block_ip(ip, reason="Manuell via Web-Interface")
                    return jsonify({"ok":True,"message":f"{ip} blockiert"})
                else:
                    fw.unblock_ip(ip)
                    return jsonify({"ok":True,"message":f"{ip} freigegeben"})
            else:
                CommandQueue.push({"action": action, "ip": ip})
                return jsonify({"ok":True,"message":f"{ip} wird {'blockiert' if action=='block' else 'freigegeben'}"})

        if action in ("mute","unmute") and ip:
            if not validate_ip(ip):
                return jsonify({"ok":False,"message":"Ungültige IP-Adresse"})
            if _is_single_process() and _mon_ref:
                if action == "mute":
                    _mon_ref.mute_ip(ip, duration_secs=int(data.get("duration",3600)))
                else:
                    _mon_ref.unmute_ip(ip)
                return jsonify({"ok":True,"message":f"{ip} {'stummgeschaltet' if action=='mute' else 'entstummt'}"})
            else:
                cmd = {"action": action, "ip": ip}
                if action == "mute":
                    cmd["duration"] = int(data.get("duration", 3600))
                CommandQueue.push(cmd)
                return jsonify({"ok":True,"message":"Wird verarbeitet"})

        if action == "set_cooldown":
            secs = int(data.get("seconds", 300))
            if not (0 <= secs <= 86400):
                return jsonify({"ok":False,"message":"Ungültiger Cooldown (0–86400s)"})
            if _is_single_process() and _mon_ref:
                _mon_ref._alert_cooldown_secs = secs
            else:
                CommandQueue.push({"action":"set_cooldown","seconds":secs})
            return jsonify({"ok":True,"message":f"Cooldown auf {secs}s gesetzt"})

        return jsonify({"ok":False,"message":"Unbekannte Aktion"})

    # ── API: Whitelist / Blacklist ─────────────────────────────────────────
    @app.route("/api/list-action", methods=["POST"])
    @auth_req
    @_csrf_required
    def api_list_action():
        """Hybrid: direkt (single-process) oder IPC (zwei Prozesse)."""
        data   = request.get_json() or {}
        list_  = data.get("list","")
        action = data.get("action","")
        ip     = data.get("ip","").strip()
        if not ip or list_ not in ("whitelist","blacklist"):
            return jsonify({"ok":False,"message":"Ungültig"})
        if not validate_ip(ip):
            return jsonify({"ok":False,"message":"Ungültige IP-Adresse"})
        cfg = Config.load()
        lst = getattr(cfg, list_)
        if action == "add" and ip not in lst:
            lst.append(ip)
        elif action == "remove" and ip in lst:
            lst.remove(ip)
        else:
            return jsonify({"ok":True,"message":"Keine Änderung nötig"})
        setattr(cfg, list_, lst)
        cfg.save()
        # Direkt anwenden wenn Monitor im selben Prozess
        if _is_single_process() and _mon_ref:
            _mon_ref.cfg = cfg
            import core as _c
            _c._rule_engine = RuleEngine(cfg)
        else:
            CommandQueue.push({"action": "reload_config"})
        return jsonify({"ok":True,"message":"Gespeichert"})

    # ── API: Regeln ────────────────────────────────────────────────────────
    @app.route("/api/rules", methods=["POST"])
    @auth_req
    @_csrf_required
    def api_rules():
        """Speichert Firewall-Regeln in Config + reload_config IPC."""
        data   = request.get_json() or {}
        action = data.get("action","")
        cfg    = Config.load()
        rules  = cfg.firewall_rules

        if action == "add":
            rule    = data.get("rule",{})
            src_ip  = rule.get("src_ip","").strip()
            port    = rule.get("port",0)
            act     = rule.get("action","")
            proto   = rule.get("proto","any")
            comment = str(rule.get("comment",""))[:200]
            if src_ip and not validate_ip(src_ip):
                return jsonify({"ok":False,"message":"Ungültige Quell-IP"})
            try:
                port = int(port)
                if not (0 <= port <= 65535): raise ValueError()
            except (ValueError,TypeError):
                return jsonify({"ok":False,"message":"Ungültiger Port (0–65535)"})
            if act not in ("block","allow","alert"):
                return jsonify({"ok":False,"message":"Ungültige Aktion"})
            if proto not in ("any","tcp","udp","icmp"):
                return jsonify({"ok":False,"message":"Ungültiges Protokoll"})
            rules.append({"proto":proto,"port":port,"src_ip":src_ip,"action":act,"comment":comment})
        elif action == "delete":
            idx = int(data.get("index",-1))
            if not (0 <= idx < len(rules)):
                return jsonify({"ok":False,"message":"Ungültiger Index"})
            rules.pop(idx)
        else:
            return jsonify({"ok":False,"message":"Unbekannte Aktion"})

        cfg.firewall_rules = rules
        cfg.save()
        if _is_single_process() and _mon_ref:
            _mon_ref.cfg = cfg
            import core as _c
            _c._rule_engine = RuleEngine(cfg)
        else:
            CommandQueue.push({"action": "reload_config"})
        return jsonify({"ok":True})

    # ── API: Log ───────────────────────────────────────────────────────────
    @app.route("/api/log")
    @auth_req
    def api_log():
        log_type = request.args.get("type","monitor")
        if log_type not in ("monitor","firewall"):
            return jsonify({"lines":["Unbekannter Log-Typ. Erlaubt: monitor, firewall"]})
        log_file = FIREWALL_LOG if log_type == "firewall" else LOG_FILE
        if not log_file.exists():
            return jsonify({"lines":["Log-Datei nicht gefunden."]})
        lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        return jsonify({"lines": lines[-500:]})

    # ── API: Config GET/POST ───────────────────────────────────────────────
    WRITABLE_FIELDS = {
        "firewall_mode","threshold","monitor_interval","average_period",
        "interface","interfaces","bpf_filter","notify_desktop","notify_log",
        "email_enabled","email_smtp","email_port","email_user","email_recipient","email_sender",
        "resolve_dns","geo_lookup","detect_portscan","portscan_limit",
        "export_csv","export_json","report_rotate",
        "syslog_enabled","syslog_host","syslog_port","syslog_protocol","syslog_tag",
        "threat_intel_enabled","threat_intel_auto_block","threat_intel_update_interval",
    }

    @app.route("/api/config", methods=["GET","POST"])
    @auth_req
    def api_config():
        if request.method == "GET":
            cfg  = Config.load()
            data = asdict(cfg)
            data.pop("email_password", None)
            return jsonify(data)
        # POST – CSRF-Prüfung via Header
        token = request.headers.get("X-CSRF-Token","")
        if not token or not hmac_compare(token, session.get("csrf_token","")):
            return jsonify({"ok":False,"message":"CSRF-Fehler"}), 403
        try:
            data = request.get_json() or {}
            data.pop("email_password", None)
            cfg = Config.load()
            for k, v in data.items():
                if k in WRITABLE_FIELDS and hasattr(cfg, k):
                    try:
                        setattr(cfg, k, v)
                    except Exception:
                        pass
            cfg.save()
            if _is_single_process() and _mon_ref:
                # Direkt anwenden – kein IPC nötig
                _mon_ref.cfg = cfg
                import core as _c
                _c._rule_engine = RuleEngine(cfg)
                if cfg.email_enabled:
                    if _c._email is None:
                        _c._email = EmailNotifier(cfg)
                    else:
                        _c._email.cfg = cfg
                else:
                    _c._email = None
                if cfg.syslog_enabled:
                    if _c._syslog is None:
                        _c._syslog = SyslogExporter(cfg)
                    else:
                        _c._syslog.cfg = cfg
                else:
                    _c._syslog = None
            else:
                CommandQueue.push({"action": "reload_config"})
            return jsonify({"ok":True,"message":"Konfiguration gespeichert"})
        except Exception as e:
            return jsonify({"ok":False,"message":str(e)})

    # ── API: Debug ─────────────────────────────────────────────────────────
    @app.route("/api/debug")
    @auth_req
    def api_debug():
        return jsonify({
            "config_exists":  CONFIG_FILE.exists(),
            "log_exists":     LOG_FILE.exists(),
            "fw_log_exists":  FIREWALL_LOG.exists(),
            "monitor_active": _mon_ref is not None,
        })

    # ── API: CSRF-Token (für JS) ───────────────────────────────────────────
    @app.route("/api/csrf-token")
    @auth_req
    def api_csrf_token():
        return jsonify({"token": _csrf_token()})

    import logging as _log
    _log.getLogger("werkzeug").setLevel(_log.WARNING)

    return app


# ════════════════════════════════════════════════════════════════════════════
# WEB-SERVER STARTEN (Gunicorn oder Flask-Dev)
# ════════════════════════════════════════════════════════════════════════════

def _start_web_server(host: str, port: int, network_mode: bool,
                      password_hash: str, ssl_context=None) -> None:
    app = _build_flask_app(network_mode, password_hash)

    # ── Windows: waitress (einziger produktionsreifer WSGI-Server für Windows) ──
    # Gunicorn läuft nicht auf Windows. Flask-Dev-Server hat mit SSL Timeout-Bugs.
    # waitress unterstützt kein natives TLS → SSL-Wrapping via ssl.wrap_socket.
    if platform.system() == "Windows":
        try:
            from waitress import serve as _waitress_serve
            import ssl as _ssl

            if ssl_context:
                cert, key = ssl_context
                # waitress selbst spricht kein TLS – wir wrappen den Socket manuell
                # via einen einfachen SSL-Wrapper-Thread
                import threading as _thr
                import socket as _sock

                ssl_ctx_obj = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx_obj.load_cert_chain(certfile=str(cert), keyfile=str(key))

                # Waitress auf localhost binden, SSL-Proxy davor schalten
                inner_port = port + 1 if port < 65534 else port - 1

                def _ssl_proxy():
                    """Minimaler SSL-Terminations-Proxy: lauscht auf port, leitet zu inner_port.
                    BUG-06 Fix (v3.9): Socket-Timeouts + Thread-Join verhindert Zombie-Threads."""
                    with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as srv:
                        srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
                        srv.settimeout(1.0)   # BUG-06: accept() nie ewig blockieren
                        srv.bind((host, port))
                        srv.listen(20)
                        active_threads: list = []
                        while True:
                            # BUG-06: Abgeschlossene Threads periodisch aufräumen
                            active_threads = [t for t in active_threads if t.is_alive()]
                            try:
                                conn, addr = srv.accept()
                            except _sock.timeout:
                                continue
                            except Exception:
                                break
                            try:
                                tls_conn = ssl_ctx_obj.wrap_socket(conn, server_side=True)
                                t = _thr.Thread(
                                    target=_proxy_forward,
                                    args=(tls_conn, "127.0.0.1", inner_port),
                                    daemon=True
                                )
                                t.start()
                                active_threads.append(t)  # BUG-06: Thread tracken
                            except Exception:
                                conn.close()

                def _proxy_forward(src, dst_host, dst_port):
                    import socket as _s
                    # BUG-06 Fix (v3.9): Timeouts auf beiden Seiten verhindern ewig blockierende Threads
                    _PROXY_TIMEOUT = 30.0
                    try:
                        src.settimeout(_PROXY_TIMEOUT)
                        with _s.create_connection((dst_host, dst_port), timeout=_PROXY_TIMEOUT) as dst:
                            dst.settimeout(_PROXY_TIMEOUT)
                            def _pipe(a, b):
                                try:
                                    while True:
                                        d = a.recv(65536)
                                        if not d: break
                                        b.sendall(d)
                                except Exception:
                                    pass
                            t = _thr.Thread(target=_pipe, args=(src, dst), daemon=True)
                            t.start()
                            _pipe(dst, src)
                            t.join(timeout=_PROXY_TIMEOUT)   # BUG-06: join mit Timeout
                    except Exception:
                        pass
                    finally:
                        try: src.close()
                        except Exception: pass

                _thr.Thread(target=_ssl_proxy, daemon=True).start()
                _waitress_serve(app, host="127.0.0.1", port=inner_port,
                                threads=4, channel_timeout=30)
            else:
                _waitress_serve(app, host=host, port=port,
                                threads=4, channel_timeout=30)
            return
        except ImportError:
            pass  # waitress nicht installiert → Flask-Fallback

        # Flask-Fallback auf Windows (ohne SSL-Probleme – HTTP only)
        if ssl_context:
            console.print("[yellow]⚠️  waitress nicht installiert. Starte ohne HTTPS.[/yellow]")
            console.print("[yellow]   Installieren: pip install waitress[/yellow]")
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
        return

    # ── Linux/macOS: Gunicorn bevorzugen ──────────────────────────────────────
    try:
        from gunicorn.app.base import BaseApplication

        class _StandaloneGunicorn(BaseApplication):
            def __init__(self, application, options=None):
                self.options     = options or {}
                self.application = application
                super().__init__()
            def load_config(self):
                for k, v in self.options.items():
                    if k in self.cfg.settings and v is not None:
                        self.cfg.set(k.lower(), v)
            def load(self):
                return self.application

        options = {
            "bind":       f"{host}:{port}",
            "workers":    2,
            "timeout":    30,
            "loglevel":   "warning",
            "accesslog":  "-",
        }
        if ssl_context:
            cert, key = ssl_context
            options["certfile"] = str(cert)
            options["keyfile"]  = str(key)

        _StandaloneGunicorn(app, options).run()
        return
    except ImportError:
        pass  # Gunicorn nicht installiert → Flask-Fallback

    # Fallback: Flask-Dev-Server (Linux ohne Gunicorn)
    app.run(
        host=host, port=port,
        debug=False, use_reloader=False, threaded=True,
        ssl_context=(str(ssl_context[0]), str(ssl_context[1])) if ssl_context else None,
    )


# ════════════════════════════════════════════════════════════════════════════
# WSGI-EINSTIEGSPUNKT FÜR GUNICORN  (Gemini-Audit Fix 3)
# Wird von netfiremon-web.service aufgerufen:
#   gunicorn "netfiremon_web:create_wsgi_app()"
# Lädt Konfiguration und baut die Flask-App ohne den interaktiven main()-Wizard.
# ════════════════════════════════════════════════════════════════════════════

def create_wsgi_app():
    """
    WSGI-Factory für Gunicorn im Zwei-Prozess-Modus (Gemini-Audit Fix 3).
    Der Monitor läuft als root (Scapy + iptables), dieser Web-Prozess als
    unprivilegierter User 'netfiremon' – keinerlei erhöhte Rechte nötig.
    """
    cfg = Config.load()

    # Web-Config laden (Passwort-Hash)
    web_cfg_file = DATA_DIR / "net_fire_monitor_web_config.json"
    pw_hash = ""
    if web_cfg_file.exists():
        try:
            pw_hash = json.loads(web_cfg_file.read_text())["password_hash"]
        except Exception:
            pass

    if not pw_hash:
        raise RuntimeError(
            "Kein Web-Passwort konfiguriert. Bitte zuerst:\n"
            "  sudo python netfiremon_web.py --setup"
        )

    app = _build_flask_app(network_mode=True, password_hash=pw_hash)
    return app


# ════════════════════════════════════════════════════════════════════════════
# SETUP-WIZARD (nur für Web-Modus)
# ════════════════════════════════════════════════════════════════════════════

def setup_wizard(cfg: Config) -> Config:
    console.print(Rule("[bold blue]NET-FIRE-MONITOR  v3.9  –  Einrichtungsassistent[/bold blue]"))
    cfg.threshold        = IntPrompt.ask("Sensitiv-Schwellenwert %", default=cfg.threshold)
    cfg.monitor_interval = IntPrompt.ask("Messintervall Sekunden",   default=cfg.monitor_interval)
    cfg.resolve_dns      = Confirm.ask("DNS-Auflösung?",             default=cfg.resolve_dns)
    cfg.detect_portscan  = Confirm.ask("Port-Scan-Erkennung?",       default=cfg.detect_portscan)

    console.print(Rule("[bold yellow]Firewall-Modus[/bold yellow]"))
    console.print("  [green]monitor[/green]  • [yellow]confirm[/yellow]  • [red]auto[/red]")
    cfg.firewall_mode = Prompt.ask("Modus", choices=["monitor","confirm","auto"], default=cfg.firewall_mode)

    console.print(Rule("[bold magenta]Threat Intelligence[/bold magenta]"))
    cfg.threat_intel_enabled   = Confirm.ask("Feeds aktivieren?", default=cfg.threat_intel_enabled)
    if cfg.threat_intel_enabled:
        cfg.threat_intel_auto_block = Confirm.ask("Bekannte IPs automatisch blockieren?",
                                                   default=cfg.threat_intel_auto_block)

    console.print(Rule("[bold cyan]E-Mail[/bold cyan]"))
    cfg.email_enabled = Confirm.ask("E-Mail-Benachrichtigungen?", default=cfg.email_enabled)
    if cfg.email_enabled:
        cfg.email_smtp      = Prompt.ask("SMTP-Server",   default=cfg.email_smtp)
        cfg.email_port      = IntPrompt.ask("SMTP-Port",  default=cfg.email_port)
        cfg.email_user      = Prompt.ask("Benutzername",  default=cfg.email_user)
        cfg.email_password  = Prompt.ask("Passwort",      password=True)
        cfg.email_recipient = Prompt.ask("Empfänger",     default=cfg.email_recipient or cfg.email_user)
        cfg.email_sender    = cfg.email_user
        ok, msg = EmailNotifier.test_connection(cfg)
        console.print(msg)

    if PLYER_OK:
        cfg.notify_desktop = Confirm.ask("Desktop-Benachrichtigungen?", default=cfg.notify_desktop)

    console.print(Rule("[bold magenta]Syslog / SIEM[/bold magenta]"))
    cfg.syslog_enabled = Confirm.ask("Syslog-Export?", default=cfg.syslog_enabled)
    if cfg.syslog_enabled:
        cfg.syslog_host     = Prompt.ask("SIEM Hostname/IP", default=cfg.syslog_host)
        cfg.syslog_port     = IntPrompt.ask("Syslog-Port",   default=cfg.syslog_port)
        cfg.syslog_protocol = Prompt.ask("Protokoll", choices=["udp","tcp"], default=cfg.syslog_protocol)
        cfg.syslog_tag      = Prompt.ask("Tag", default=cfg.syslog_tag)
        ok, msg = SyslogExporter.test_connection(cfg)
        console.print(msg)

    console.print()
    console.print(Rule("[bold red]Netzwerk-Sicherheit[/bold red]"))
    console.print("[dim]  Ist ein Reverse-Proxy (nginx, Caddy, Traefik) vorgeschaltet?[/dim]")
    console.print("[dim]  Nur aktivieren wenn das Tool HINTER einem Proxy betrieben wird.[/dim]")
    console.print("[dim]  Falsche Einstellung ermöglicht IP-Spoofing → Brute-Force-Bypass![/dim]")
    cfg.behind_reverse_proxy = Confirm.ask(
        "Reverse-Proxy vorgeschaltet?", default=cfg.behind_reverse_proxy
    )

    console.print()
    console.print(Rule("[bold blue]Netzwerk-Interface & BPF-Filter[/bold blue]"))
    console.print(f"[dim]  Aktuelles Interface: {cfg.interface or 'alle'}[/dim]")
    console.print("[dim]  Leer lassen = alle Interfaces überwachen[/dim]")
    cfg.interface = Prompt.ask("Interface (leer = alle)", default=cfg.interface or "")

    console.print(f"[dim]  Aktueller BPF-Filter: {cfg.bpf_filter}[/dim]")
    if platform.system() == "Windows":
        console.print("[yellow]  ⚠️  Unter Windows nur einfache Filter (z.B. 'ip or ip6')[/yellow]")
    else:
        console.print("[dim]  Empfohlen Linux/macOS: tcp[tcpflags] & (tcp-syn) != 0 or icmp or udp[/dim]")
    cfg.bpf_filter = Prompt.ask("BPF-Filter", default=cfg.bpf_filter)

    cfg.save()
    console.print("[green]✅  Konfiguration gespeichert.[/green]")
    return cfg


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    global _mon_ref
    auto_mode   = "--auto"  in sys.argv
    force_setup = "--setup" in sys.argv

    console.print()
    console.print(Panel.fit(
        "[bold white]NET-FIRE-MONITOR  v3.9  –  Web-Modus[/bold white]\n"
        "[dim]Flask · Gunicorn · HTTPS · CSRF-Schutz[/dim]",
        border_style="blue", title="[bold blue]Willkommen[/bold blue]",
    ))

    if platform.system() in ("Linux","Darwin") and os.geteuid() != 0:
        console.print("[bold red]❌  Root-Rechte erforderlich. Bitte mit sudo starten![/bold red]")
        sys.exit(1)

    cfg = Config.load()

    if force_setup or (not auto_mode and (
        not CONFIG_FILE.exists() or Confirm.ask("Einstellungen anpassen?", default=False)
    )):
        cfg = setup_wizard(cfg)

    # ── Engines ────────────────────────────────────────────────────────────
    console.print("\n[cyan]⚙️   Initialisiere Engines …[/cyan]")
    _core._firewall    = FirewallEngine()
    _core._email       = EmailNotifier(cfg) if cfg.email_enabled else None
    _core._rule_engine = RuleEngine(cfg)

    if cfg.threat_intel_enabled:
        _core._threat_intel = ThreatIntelManager(cfg)
        time.sleep(1)
        console.print(f"  ☠️   Threat Intel: [cyan]{_core._threat_intel.get_count():,} Einträge[/cyan]")

    if cfg.syslog_enabled:
        _core._syslog = SyslogExporter(cfg)

    # ── Neustart-Wiederherstellung ─────────────────────────────────────────
    console.print("\n[cyan]🔄  Stelle letzten Zustand wieder her …[/cyan]")
    stats = restore_on_startup(_core._firewall)
    if stats["restored_blocks"] > 0:
        console.print(f"  🔒 [yellow]{stats['restored_blocks']} blockierte IP(s) wiederhergestellt[/yellow]")
    if stats["restored_rules"] > 0:
        console.print(f"  📋 [yellow]{stats['restored_rules']} Firewall-Regel(n) wiederhergestellt[/yellow]")
    if stats["whitelist"] > 0 or stats["blacklist"] > 0:
        console.print(f"  🛡️  Whitelist ({stats['whitelist']}) / Blacklist ({stats['blacklist']}) geprüft")
    if all(v == 0 for v in stats.values()):
        console.print("  ✅ Kein vorheriger Zustand – erster Start oder frische Session.")

    # ── Baseline ──────────────────────────────────────────────────────────
    mon = NetworkMonitor(cfg)
    _mon_ref = mon
    console.print(f"\n[cyan]🔍  Überprüfe Baseline …[/cyan]")

    with Progress(TextColumn("[cyan]{task.description}"), BarColumn(),
                  TextColumn("[cyan]{task.completed}/{task.total} s"),
                  console=console, transient=True) as prog:
        task = prog.add_task("Baseline", total=cfg.average_period)
        done = threading.Event()
        def _p():
            for _ in range(cfg.average_period):
                if done.is_set(): break
                time.sleep(1); prog.advance(task, 1)
        t = threading.Thread(target=_p, daemon=True); t.start()
        from_snapshot = mon.measure_baseline(use_saved=True)
        done.set(); t.join()

    if from_snapshot:
        console.print(f"[green]✅  Baseline aus Snapshot: {mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}[/green]")
        console.print("[dim]   (Kein Warten nötig – gespeicherte Baseline verwendet)[/dim]")
    else:
        console.print(f"[green]✅  Baseline gemessen: {mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}[/green]")

    # ── Start-Modus ────────────────────────────────────────────────────────
    if not auto_mode:
        console.print(Rule("[bold blue]Start-Modus[/bold blue]"))
        console.print("  [cyan]0[/cyan]  –  Nur Terminal-Dashboard")
        console.print("  [cyan]1[/cyan]  –  Terminal + Web-Interface")
        console.print("  [cyan]2[/cyan]  –  Nur Web-Interface")
        modus = Prompt.ask("Modus", choices=["0","1","2"], default="0")
    else:
        modus = "2"  # Im Auto-Modus: nur Web

    web_host = "127.0.0.1"
    web_port = 5000
    network_mode = False
    pw_hash = ""
    ssl_ctx = None

    if modus in ("1","2"):
        console.print(Rule("[bold cyan]Web-Interface Konfiguration[/bold cyan]"))

        # Passwort aus gespeicherter Web-Config laden (falls vorhanden)
        web_cfg_file = DATA_DIR / "net_fire_monitor_web_config.json"
        if web_cfg_file.exists():
            try:
                pw_hash = json.loads(web_cfg_file.read_text())["password_hash"]
            except Exception:
                pw_hash = ""

        if not auto_mode:
            net = Confirm.ask("Im ganzen Netzwerk erreichbar?", default=False)
        else:
            net = True

        if net:
            network_mode = True
            web_host     = "0.0.0.0"
            if not pw_hash:
                pw_hash = _setup_web_password()
            web_port = int(os.environ.get("NFM_WEB_PORT", "5443"))

            # HTTPS-Zertifikat
            cert_dir  = SCRIPT_DIR / "certs"
            cert, key = _ensure_tls_cert(cert_dir)
            if cert.exists() and key.exists():
                ssl_ctx = (cert, key)
                console.print("[green]🔐  HTTPS aktiv[/green]")
        else:
            web_port = int(os.environ.get("NFM_WEB_PORT", "5000"))
            console.print("[dim]  Nur lokal erreichbar – kein Passwort erforderlich.[/dim]")

        if not auto_mode:
            web_port = IntPrompt.ask("Web-Port", default=web_port)

        # Web-Server in eigenem Thread
        wt = threading.Thread(
            target=_start_web_server,
            args=(web_host, web_port, network_mode, pw_hash, ssl_ctx),
            daemon=True,
        )
        wt.start()
        time.sleep(1.5)

        proto = "https" if ssl_ctx else "http"
        url   = f"{proto}://localhost:{web_port}"
        console.print(f"\n[green]✅  Web-Interface: [bold]{url}[/bold][/green]")
        if network_mode:
            console.print(f"[dim]   Netzwerk: {proto}://<deine-IP>:{web_port}[/dim]")

        try:
            import webbrowser
            threading.Timer(1.5, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    # ── Monitor-Thread starten ─────────────────────────────────────────────
    mon_thread = threading.Thread(target=mon.run_monitor_loop, daemon=True)
    mon_thread.start()

    if modus == "2":
        console.print("[dim]Web-Interface läuft. [Strg+C] zum Beenden[/dim]")
        try:
            while mon_thread.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        # Terminal-Dashboard (Modus 0 oder 1)
        from netfiremon_terminal import build_layout
        console.print("[dim]Live-Dashboard startet … [Strg+C] zum Beenden[/dim]")
        time.sleep(0.5)
        with Live(build_layout(mon, cfg), console=console, refresh_per_second=2, screen=True) as live:
            try:
                while mon_thread.is_alive():
                    live.update(build_layout(mon, cfg))
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass

    # ── Abschluss ──────────────────────────────────────────────────────────
    console.print("\n[bold green]Net-Fire-Monitor beendet.[/bold green]")
    fw = _core._firewall
    if fw and fw.blocked_ips:
        console.print(f"[yellow]⚠️   {len(fw.blocked_ips)} IP(s) sind noch blockiert![/yellow]")
        if auto_mode or Confirm.ask("Alle Firewall-Regeln aufheben?", default=True):
            fw.cleanup_all()
            console.print("[green]✅  Alle Regeln entfernt.[/green]")

    save_state(mon)
    console.print("[green]✅  Snapshot gespeichert.[/green]")


if __name__ == "__main__":
    main()
