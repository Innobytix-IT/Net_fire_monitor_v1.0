# Net-Fire-Monitor v1.0 – OpenScan Projekt

> Netzwerk-Monitor + aktives Intrusion Prevention System (IPS) mit Live-Dashboard, automatischer Firewall-Steuerung, Threat Intelligence und E-Mail-Benachrichtigung.

**(C) 2023–2026 Manuel Person**

---

## Inhaltsverzeichnis

1. [Was ist Net-Fire-Monitor?](#was-ist-es)
2. [Unterschiede zu Net-Monitor v2.0](#unterschiede)
3. [Voraussetzungen](#voraussetzungen)
4. [Installation & Erster Start](#installation)
5. [E-Mail-Passwort sicher einrichten](#passwort)
6. [Konfiguration](#konfiguration)
7. [Firewall-Modi](#firewall-modi)
8. [Threat Intelligence](#threat-intel)
9. [Firewall-Regeln definieren](#regeln)
10. [Dashboard-Übersicht](#dashboard)
11. [Häufige Fragen (FAQ)](#faq)

---

## Was ist Net-Fire-Monitor? <a name="was-ist-es"></a>

Net-Fire-Monitor ist die Weiterentwicklung von Net-Monitor v2.0 – von einem passiven Netzwerk-Monitor zu einem **aktiven Intrusion Prevention System (IPS)**.

Das Tool kombiniert:
- 📡 **Netzwerk-Sniffer** (Scapy, IPv4 + IPv6)
- 🔥 **Firewall-Engine** (Windows netsh / Linux iptables / macOS pfctl)
- ☠️ **Threat Intelligence** (Feodo Tracker, CINS Army, Spamhaus DROP)
- 📧 **E-Mail-Benachrichtigung** (SMTP, alle Provider)
- 📋 **Regel-Engine** (Port/Protokoll-Regeln)
- 📊 **Live-Dashboard** (Rich Terminal UI)

---

## Unterschiede zu Net-Monitor v2.0 <a name="unterschiede"></a>

| Feature | Net-Monitor v2.0 | Net-Fire-Monitor v1.0 |
|---------|-----------------|----------------------|
| Netzwerk-Überwachung | ✅ | ✅ |
| Live-Dashboard | ✅ | ✅ |
| Geo-IP & DNS | ✅ | ✅ |
| Port-Scan-Erkennung | ✅ | ✅ |
| **Firewall-Steuerung** | ❌ | ✅ Windows + Linux + macOS |
| **Firewall-Modi** | ❌ | ✅ monitor / confirm / auto |
| **Threat Intelligence** | ❌ | ✅ 15.000+ bekannte böse IPs |
| **E-Mail-Benachrichtigung** | ❌ | ✅ HTML-E-Mails via SMTP |
| **Regel-Engine** | ❌ | ✅ Port/Protokoll-Regeln |
| **Geblockte IPs im Dashboard** | ❌ | ✅ |
| **Firewall Rate Limiting** | ❌ | ✅ DDoS-resistent |
| **Log Rotation** | ✅ | ✅ erweitert |
| Passwort-Sicherheit | ❌ Klartext | ✅ Umgebungsvariable |

---

## Voraussetzungen <a name="voraussetzungen"></a>

- **Python** 3.10 oder neuer
- **Windows**: Npcap ([npcap.com](https://npcap.com/#download)) + **Administratorrechte** (für Firewall-Regeln zwingend!)
- **Linux/macOS**: Root-Rechte (`sudo`) + `iptables` / `pfctl` vorinstalliert

Python-Pakete werden beim ersten Start automatisch installiert:
```
scapy, rich, plyer, geoip2, requests
```

### Optional: Geo-IP-Datenbank

Für die Länderanzeige wird die kostenlose **GeoLite2-City**-Datenbank von MaxMind benötigt:

1. Konto erstellen: [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. `GeoLite2-City.mmdb` herunterladen
3. Datei ins gleiche Verzeichnis wie `net_fire_monitor_v1.0.py` kopieren

---

## Installation & Erster Start <a name="installation"></a>

```bash
# Linux / macOS (Root erforderlich für Firewall + Sniffing):
sudo python3 net_fire_monitor_v1.0.py

# Windows (als Administrator ausführen!):
python net_fire_monitor_v1.0.py
```

Beim **ersten Start** erscheint der Einrichtungsassistent:

- **Schritt 1**: Python-Pakete installieren
- **Schritt 2**: Npcap-Anleitung (nur Windows)
- **Schritt 3**: GeoLite2-Datenbank einrichten

Danach startet der **Konfigurations-Wizard** mit allen Einstellungen.

---

## E-Mail-Passwort sicher einrichten <a name="passwort"></a>

Das E-Mail-Passwort wird **nicht** in der Config-Datei gespeichert. Es wird über die Umgebungsvariable `NFM_EMAIL_PASSWORD` bereitgestellt.

### Gmail: App-Passwort erstellen (empfohlen)

> ⚠️ Dein echtes Google-Passwort funktioniert hier **nicht**. Google verlangt ein App-Passwort.

1. Google-Konto → **Sicherheit** → 2-Faktor-Authentifizierung aktivieren
2. Aufrufen: [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Name: `NetFireMonitor` → **Erstellen**
4. Den 16-stelligen Code notieren (z.B. `abcd efgh ijkl mnop`)

### Umgebungsvariable setzen

**Windows** (dauerhaft, als Administrator in CMD):
```cmd
setx NFM_EMAIL_PASSWORD "abcdefghijklmnop" /M
```

**Linux / macOS** (dauerhaft in `~/.bashrc` oder `~/.zshrc`):
```bash
export NFM_EMAIL_PASSWORD="abcdefghijklmnop"
```

**Nur für eine Session** (alle Plattformen):
```bash
# Linux/macOS:
NFM_EMAIL_PASSWORD="abcdefghijklmnop" sudo -E python3 net_fire_monitor_v1.0.py

# Windows CMD:
set NFM_EMAIL_PASSWORD=abcdefghijklmnop && python net_fire_monitor_v1.0.py
```

---

## Konfiguration <a name="konfiguration"></a>

Alle Einstellungen werden in `net_fire_monitor_config.json` gespeichert.

> ⚠️ **Diese Datei nicht auf GitHub hochladen!** Sie enthält deine E-Mail-Adresse und Whitelist-IPs. Die mitgelieferte `.gitignore` schützt sie automatisch.

### Alle Parameter

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `average_period` | `120` | Baseline-Messdauer in Sekunden |
| `monitor_interval` | `30` | Messintervall in Sekunden |
| `threshold` | `20` | Alarm-Schwellenwert in % über Baseline |
| `bpf_filter` | `"ip or ip6"` | Scapy BPF-Filter |
| `interface` | `""` | Netzwerk-Interface (`""` = alle) |
| `notify_desktop` | `true` | Desktop-Benachrichtigungen |
| `notify_log` | `true` | Log-Datei-Einträge |
| `resolve_dns` | `true` | DNS-Auflösung im Dashboard |
| `geo_lookup` | `true` | Geo-IP-Ländererkennung |
| `detect_portscan` | `true` | Port-Scan-Erkennung |
| `portscan_limit` | `100` | Ports pro 10s → Portscan-Alarm |
| `whitelist` | `[...]` | IPs ohne Traffic-Alarm |
| `blacklist` | `[]` | IPs mit sofortigem Alarm |
| `firewall_mode` | `"monitor"` | Firewall-Modus (siehe unten) |
| `threat_intel_enabled` | `true` | Threat-Intel-Feeds aktivieren |
| `threat_intel_auto_block` | `false` | Bekannte böse IPs auto-blocken |
| `email_enabled` | `false` | E-Mail-Benachrichtigungen |
| `email_smtp` | `"smtp.gmail.com"` | SMTP-Server |
| `email_port` | `587` | SMTP-Port |
| `email_user` | `""` | Absender E-Mail |
| `email_recipient` | `""` | Empfänger E-Mail |
| `export_csv` | `true` | CSV-Report speichern |
| `report_rotate` | `7` | Reports nach N Tagen löschen |

---

## Firewall-Modi <a name="firewall-modi"></a>

Der Modus wird beim Setup gewählt und kann jederzeit in der Config geändert werden.

### 👁 monitor (Standard)
Nur beobachten. Keine automatischen Eingriffe. Ideal zum Einstieg.

### ⚡ confirm
Bei einem Alarm wird eine E-Mail gesendet. Du entscheidest manuell ob blockiert wird. Erfordert funktionierende E-Mail-Konfiguration.

### 🔥 auto
Verdächtige externe IPs werden **sofort automatisch blockiert**. Dabei gelten folgende Schutzmaßnahmen:
- IPs auf der **Whitelist** werden nie blockiert
- **Private IPs** (LAN) werden nie blockiert
- **Rate Limiting**: max. 30 Blocks pro Minute, min. 10s Abstand pro IP
- Beim Beenden wird gefragt ob alle Regeln aufgehoben werden sollen

> ⚠️ Im `auto`-Modus können durch False Positives legitime Server temporär blockiert werden. Whitelist sorgfältig pflegen!

---

## Threat Intelligence <a name="threat-intel"></a>

Das Tool lädt automatisch Listen bekannter Bedrohungs-IPs von öffentlichen Quellen:

| Feed | Beschreibung |
|------|-------------|
| **Feodo Tracker** | Botnet Command & Control Server |
| **CINS Army** | Bekannte Angreifer-IPs |
| **Spamhaus DROP** | Gestohlene / kompromittierte Netze |

- Feeds werden alle **60 Minuten** aktualisiert
- Lokales Caching in `threat_intel_cache.txt` → schneller Start
- Beim Start werden typischerweise **15.000+** bekannte böse IPs geladen

---

## Firewall-Regeln definieren <a name="regeln"></a>

Regeln werden als Liste in der Config unter `firewall_rules` definiert:

```json
"firewall_rules": [
  {
    "proto": "tcp",
    "port": 23,
    "src_ip": "",
    "action": "block",
    "comment": "Telnet immer blockieren"
  },
  {
    "proto": "tcp",
    "port": 3389,
    "src_ip": "",
    "action": "alert",
    "comment": "RDP-Zugriff immer alarmieren"
  },
  {
    "proto": "any",
    "port": 0,
    "src_ip": "10.0.0.99",
    "action": "block",
    "comment": "Bestimmte IP immer blockieren"
  }
]
```

| Feld | Werte | Beschreibung |
|------|-------|-------------|
| `proto` | `tcp`, `udp`, `icmp`, `any` | Protokoll |
| `port` | `0`–`65535` (`0` = alle) | Ziel-Port |
| `src_ip` | IP oder `""` für alle | Quell-IP |
| `action` | `block`, `alert`, `allow` | Aktion |

---

## Dashboard-Übersicht <a name="dashboard"></a>

![Net-Fire-Monitor Dashboard](Screenshots/Screenshot_1.png)

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  NET-FIRE-MONITOR v1.0  │  Interface: alle  │  Modus: 🔥 AUTO  │  Zeit     ║
║                         │  Threat-Intel: 15.234 IPs                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 📈 Verlauf (letzte 60 Messungen)                                            ║
╠══════════════╦══════════════════╦════════════════════════════════════════════╣
║ 📊 Statistik ║ 🔌 Protokolle    ║ 🚨 Alarme                                 ║
╠══════════════╩══════════════════╬════════════════════════════════════════════╣
║ 🔝 Top-Talker                   ║ 🔒 Top-Ports                              ║
╠═════════════════════════════════╩════════════════════════════════════════════╣
║ 🛡️  Geblockte IPs                                                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 📦 Letzte Pakete  (🌍 Geo-IP aktiv)                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Geo-IP Farbcodes

| Farbe | Bedeutung |
|-------|-----------|
| 🟢 Grün | LAN oder bekannte Cloud/CDN-Region (DE, US, NL, ...) |
| 🟡 Gelb | Unbekannte Region |
| ⬛ Dim | Nicht auflösbar |

---

## Häufige Fragen (FAQ) <a name="faq"></a>

**Das Tool startet aber blockiert keine IPs.**
→ Prüfe ob du als Administrator (Windows) bzw. mit `sudo` (Linux/macOS) gestartet hast. Firewall-Regeln erfordern erhöhte Rechte.

**E-Mail-Versand schlägt fehl (`BadCredentials`).**
→ Bei Gmail kein echtes Passwort verwenden, sondern ein App-Passwort erstellen. Siehe [E-Mail-Passwort einrichten](#passwort).

**Ich habe mich selbst ausgesperrt / eine IP fälschlicherweise blockiert.**
→ Tool beenden (Strg+C) → beim Beenden "Alle Firewall-Regeln aufheben?" mit `y` bestätigen. Alternativ manuell:
```cmd
# Windows:
netsh advfirewall firewall delete rule name="NetFireMon_Block_1.2.3.4"

# Linux:
iptables -D INPUT -s 1.2.3.4 -j DROP
```

**Die Threat-Intel-Liste ist leer / wird nicht geladen.**
→ Internetverbindung prüfen. Beim nächsten Start wird aus dem Cache (`threat_intel_cache.txt`) geladen falls vorhanden.

**Zu viele Alarme im `auto`-Modus.**
→ Whitelist in der Config erweitern. Den `threshold`-Wert erhöhen (z.B. auf 50%). Oder auf `confirm`-Modus wechseln.

**Wie setze ich das Passwort dauerhaft?**
→ Siehe [E-Mail-Passwort einrichten](#passwort) – Umgebungsvariable `NFM_EMAIL_PASSWORD` dauerhaft in den System-Einstellungen setzen.

---

## Sicherheitshinweise

- **Nur im eigenen Netzwerk betreiben!** Paketerfassung in fremden Netzwerken ist illegal.
- Die Config-Datei enthält persönliche Daten – **nicht auf GitHub hochladen** (`.gitignore` ist beigefügt).
- Das E-Mail-Passwort wird **nicht** in der Config gespeichert, sondern über die Umgebungsvariable `NFM_EMAIL_PASSWORD` geladen.
- Im `auto`-Modus können durch False Positives legitime IPs blockiert werden. Whitelist sorgfältig pflegen.

---

*Net-Fire-Monitor ist ein Open-Source-Projekt und wird ohne Gewährleistung bereitgestellt.*
*Verwendung auf eigene Verantwortung – Paketerfassung nur in eigenen Netzwerken!*
