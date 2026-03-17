#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  Net-Fire-Monitor v3.0 – Installations-Skript (Linux)
#
#  Gemini-Audit Fix 3: Zwei-Prozess-Architektur
#   • netfiremon.service     → root (Scapy + iptables)
#   • netfiremon-web.service → User "netfiremon" (kein root!)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

INSTALL_DIR="/opt/netfiremon"
PYTHON="python3"
WEB_USER="netfiremon"
WEB_GROUP="netfiremon"

if [ "$(id -u)" -ne 0 ]; then
    echo "❌  Bitte als root ausführen: sudo bash install.sh"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Net-Fire-Monitor v3.0 – Installation              ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Schritt 1: Dedizierter System-User für Web-Prozess ───────
echo "👤  Lege System-User '$WEB_USER' an (kein Login, kein Home) …"
if ! id "$WEB_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$WEB_USER"
    echo "✅  User '$WEB_USER' angelegt."
else
    echo "✅  User '$WEB_USER' existiert bereits."
fi

# ── Schritt 2: Verzeichnis anlegen und Rechte setzen ─────────
echo ""
echo "📁  Erstelle Installationsverzeichnis: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/certs"

# ── DATA_DIR: veränderliche Dateien (Gemini-Audit Fix 1) ─────────────────
# Code-Verzeichnis (INSTALL_DIR) → root:root, 750 (kein Schreiben für Web-User)
# Data-Verzeichnis (data/)       → root:netfiremon, 770 (Web-User darf schreiben)
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/data/reports"
mkdir -p "$INSTALL_DIR/data/cmd_queue"

# Dateien kopieren
cp core.py                  "$INSTALL_DIR/"
cp netfiremon_terminal.py   "$INSTALL_DIR/"
cp netfiremon_web.py        "$INSTALL_DIR/"
cp requirements.txt         "$INSTALL_DIR/"

if [ -d "web" ]; then
    cp -r web "$INSTALL_DIR/"
fi

if [ -f "GeoLite2-City.mmdb" ]; then
    cp GeoLite2-City.mmdb "$INSTALL_DIR/"
    echo "✅  GeoLite2-City.mmdb gefunden und kopiert."
else
    echo "⚠️   GeoLite2-City.mmdb nicht gefunden."
    echo "    → https://www.maxmind.com/en/geolite2/signup"
fi

# Dateirechte setzen:
#   INSTALL_DIR/          root:netfiremon 750 → Web-User darf nur lesen
#   INSTALL_DIR/data/     root:netfiremon 770 → Web-User darf schreiben
#   INSTALL_DIR/certs/    root:netfiremon 750 → Web-User darf nur lesen
chown -R root:$WEB_GROUP "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod -R 640 "$INSTALL_DIR"/*.py "$INSTALL_DIR/requirements.txt" 2>/dev/null || true

# data/ und Unterverzeichnisse: Web-User darf schreiben
chmod 770 "$INSTALL_DIR/data"
chmod 770 "$INSTALL_DIR/data/reports"
chmod 770 "$INSTALL_DIR/data/cmd_queue"
chown root:$WEB_GROUP "$INSTALL_DIR/data" \
                      "$INSTALL_DIR/data/reports" \
                      "$INSTALL_DIR/data/cmd_queue"

# certs/: Web-User darf nur lesen (Gunicorn braucht Lesezugriff)
chmod 750 "$INSTALL_DIR/certs"
chown root:$WEB_GROUP "$INSTALL_DIR/certs"

echo "✅  Dateirechte gesetzt."

# ── Schritt 3: Virtual Environment ──────────────────────────
echo ""
echo "🐍  Erstelle Python-Virtual-Environment …"
cd "$INSTALL_DIR"
$PYTHON -m venv .venv
chown -R root:$WEB_GROUP .venv
chmod -R g+rX .venv
echo "✅  venv erstellt."

# ── Schritt 4: Pakete installieren ──────────────────────────
echo ""
echo "📦  Installiere Abhängigkeiten …"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt
echo "✅  Pakete installiert."

# ── Schritt 5: systemd-Dienste registrieren ─────────────────
echo ""
echo "⚙️   Registriere systemd-Dienste …"

# Monitor-Dienst (root)
cp netfiremon.service /etc/systemd/system/netfiremon.service
sed -i "s|/opt/netfiremon|${INSTALL_DIR}|g" /etc/systemd/system/netfiremon.service

# Web-Dienst (netfiremon user)
cp netfiremon-web.service /etc/systemd/system/netfiremon-web.service
sed -i "s|/opt/netfiremon|${INSTALL_DIR}|g" /etc/systemd/system/netfiremon-web.service
sed -i "s|User=netfiremon|User=${WEB_USER}|g" /etc/systemd/system/netfiremon-web.service
sed -i "s|Group=netfiremon|Group=${WEB_GROUP}|g" /etc/systemd/system/netfiremon-web.service

systemctl daemon-reload
echo "✅  Dienste registriert."

# ── Schritt 6: Ersteinrichtung ───────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧  Konfiguration einrichten …"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd "$INSTALL_DIR"
.venv/bin/python netfiremon_web.py --setup

# Nach dem Setup: Rechte für neu erstellte Dateien in data/ korrigieren
chown -R root:$WEB_GROUP "$INSTALL_DIR/data" 2>/dev/null || true
chmod -R 660 "$INSTALL_DIR/data"/*.json 2>/dev/null || true
chmod -R 660 "$INSTALL_DIR/data/".* 2>/dev/null || true
chmod 770 "$INSTALL_DIR/data" "$INSTALL_DIR/data/reports" "$INSTALL_DIR/data/cmd_queue"

# ── Schritt 7: Dienste starten ───────────────────────────────
echo ""
echo "🚀  Starte Dienste …"
systemctl enable netfiremon netfiremon-web
systemctl start  netfiremon
sleep 3
systemctl start  netfiremon-web
sleep 2

echo ""
if systemctl is-active --quiet netfiremon; then
    echo "✅  Monitor-Dienst läuft!"
else
    echo "⚠️   Monitor-Dienst nicht gestartet. Logs: journalctl -u netfiremon -n 50"
fi
if systemctl is-active --quiet netfiremon-web; then
    echo "✅  Web-Dienst läuft!"
else
    echo "⚠️   Web-Dienst nicht gestartet. Logs: journalctl -u netfiremon-web -n 50"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "✅  Installation abgeschlossen!"
echo ""
echo "  Dienste steuern:"
echo "    sudo systemctl status netfiremon netfiremon-web"
echo "    sudo systemctl restart netfiremon netfiremon-web"
echo ""
echo "  Logs:"
echo "    sudo journalctl -u netfiremon -f"
echo "    sudo journalctl -u netfiremon-web -f"
echo ""
echo "  Web-Interface: https://<IP>:5443"
echo "  (Browser-Warnung beim Self-Signed-Zertifikat ist normal)"
echo "═══════════════════════════════════════════════════════"
echo ""
