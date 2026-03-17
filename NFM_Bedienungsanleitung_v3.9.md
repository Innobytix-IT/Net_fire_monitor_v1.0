# NET-FIRE-MONITOR v3.9

**Vollständige Bedienungsanleitung**

Intrusion Prevention System & Network Monitor

**Windows • Linux • macOS**

© 2023–2026 Manuel Person – Innobytix-IT

---

## Inhaltsverzeichnis

- [1. Einführung](#1-einführung)
  - [1.1 Was ist Net-Fire-Monitor?](#11-was-ist-net-fire-monitor)
  - [1.2 Anwendungsszenarien](#12-anwendungsszenarien)
- [2. Systemvoraussetzungen](#2-systemvoraussetzungen)
  - [2.1 Hardware-Anforderungen](#21-hardware-anforderungen)
  - [2.2 Betriebssystem-Anforderungen](#22-betriebssystem-anforderungen)
- [3. Installation](#3-installation)
  - [3.1 Linux-Installation (Automatisch)](#31-linux-installation-automatisch)
  - [3.2 Windows-Installation](#32-windows-installation)
  - [3.3 macOS-Installation](#33-macos-installation)
- [4. Dedizierte IPS-Box (Bridge-Mode Setup)](#4-dedizierte-ips-box-bridge-mode-setup)
  - [4.1 Netzwerk-Topologie](#41-netzwerk-topologie)
  - [4.2 Hardware-Anforderungen für Bridge-Box](#42-hardware-anforderungen-für-bridge-box)
  - [4.3 Linux-Bridge-Konfiguration](#43-linux-bridge-konfiguration)
  - [4.4 br_netfilter aktivieren (KRITISCH!)](#44-br_netfilter-aktivieren-kritisch)
  - [4.5 NFM im Bridge-Mode installieren](#45-nfm-im-bridge-mode-installieren)
- [5. Konfiguration & Einstellungen](#5-konfiguration--einstellungen)
  - [5.1 Firewall-Modi](#51-firewall-modi)
  - [5.2 Threshold (Schwellwert) richtig einstellen](#52-threshold-schwellwert-richtig-einstellen)
- [6. BPF-Filter (Berkeley Packet Filter)](#6-bpf-filter-berkeley-packet-filter)
  - [6.1 Grundlagen](#61-grundlagen)
  - [6.2 Standard-Filter (Empfohlen)](#62-standard-filter-empfohlen)
  - [6.3 Erweiterte BPF-Filter-Beispiele](#63-erweiterte-bpf-filter-beispiele)
  - [6.4 BPF-Filter im NFM setzen](#64-bpf-filter-im-nfm-setzen)
  - [6.5 BPF-Filter testen & validieren](#65-bpf-filter-testen--validieren)
- [7. Betrieb & Bedienung](#7-betrieb--bedienung)
  - [7.1 Web-Interface](#71-web-interface)
  - [7.2 Terminal-Dashboard](#72-terminal-dashboard)
  - [7.3 E-Mail-Benachrichtigungen einrichten](#73-e-mail-benachrichtigungen-einrichten)
- [8. Best Practices & Sicherheit](#8-best-practices--sicherheit)
  - [8.1 OS-Hardening für die IPS-Box](#81-os-hardening-für-die-ips-box)
  - [8.2 Whitelist-Strategie](#82-whitelist-strategie)
  - [8.3 Monitoring & Wartung](#83-monitoring--wartung)
- [9. Troubleshooting](#9-troubleshooting)
  - [9.1 Häufige Probleme](#91-häufige-probleme)
  - [9.2 Log-Analyse](#92-log-analyse)
- [10. Anhang](#10-anhang)
  - [10.1 Schnellreferenz: Wichtigste Befehle](#101-schnellreferenz-wichtigste-befehle)
  - [10.2 Weitere Ressourcen](#102-weitere-ressourcen)

---

## 1. Einführung

### 1.1 Was ist Net-Fire-Monitor?

Net-Fire-Monitor (NFM) ist ein aktives **Netzwerk-Monitor- und Intrusion-Prevention-System (IPS)** für Linux, Windows und macOS. Es erfasst den gesamten Netzwerkverkehr in Echtzeit, erkennt Anomalien, Angriffe und verdächtiges Verhalten und kann Angreifer-IPs automatisch über die Systemfirewall blockieren.

> ℹ️ **INFO:** NFM arbeitet auf Layer 2/3 des OSI-Modells und analysiert jeden einzelnen Netzwerk-Frame bevor er das Betriebssystem erreicht. Dies ermöglicht präventive Blockierung noch bevor schädlicher Traffic Ihre Systeme erreicht.

#### Kern-Features

- **Echtzeit-Paketanalyse** mit Scapy (Layer 2–7)
- **Automatische Angriffserkennung:** Port-Scans, SYN-Floods, DDoS-Muster, Anomalie-Erkennung
- **Threat Intelligence Integration:** Automatischer Abgleich mit bekannten Bedrohungsdatenbanken
- **Aktive Verteidigung:** Automatische Firewall-Blockierung (iptables/nftables, Windows Firewall, macOS pfctl)
- **Geo-IP-Lokalisierung:** Zeigt Herkunftsland und Stadt jeder IP
- **Zwei Bedienoberflächen:** Terminal-Dashboard (Rich-basiert) und HTTPS-Web-Interface
- **E-Mail-Benachrichtigungen:** Automatische Alarme mit vollständiger IP-Analyse
- **Syslog-Export:** CEF-Format für SIEM-Integration

### 1.2 Anwendungsszenarien

#### Szenario A: Host-basierte Überwachung

NFM läuft direkt auf einem Windows-PC, Linux-Server oder macOS-System und schützt diesen Host vor eingehenden Angriffen.

> ✅ **IDEAL FÜR:** Einzelne Server, Entwickler-Workstations, Home-Office-PCs

#### Szenario B: Dedizierte IPS-Box (Transparent Bridge)

NFM läuft auf einer dedizierten Linux-Box, die als transparente Netzwerkbrücke zwischen Router und internem Netzwerk platziert wird. Der gesamte Traffic des Netzwerks fließt durch die IPS-Box und wird analysiert.

> ⚠️ **WICHTIG:** Dies ist die professionelle Enterprise-Lösung und wird in Kapitel 4 detailliert erklärt!

> ✅ **IDEAL FÜR:** Firmen-Netzwerke, kleine Rechenzentren, kritische Infrastrukturen

#### Szenario C: Virtual Machine Monitor

NFM läuft in einer VM (z.B. Proxmox, VMware, Hyper-V) und überwacht den Traffic des Hypervisor-Hosts oder der VM-Bridge.

> ✅ **IDEAL FÜR:** Virtualisierte Umgebungen, Lab-Setups, Test-Szenarien

---

## 2. Systemvoraussetzungen

### 2.1 Hardware-Anforderungen

| Komponente | Minimum | Empfohlen |
|------------|---------|-----------|
| CPU | Dual-Core 2 GHz | Quad-Core 3+ GHz |
| RAM | 2 GB | 4–8 GB |
| Festplatte | 500 MB | 5–10 GB (Logs) |
| Netzwerkkarte | 1x GbE (Host-Modus) | **2x GbE (Bridge-Modus)** |

> ⚠️ **WARNUNG:** Für Bridge-Mode (Szenario B) werden ZWEI Netzwerkkarten benötigt! Eine für WAN (zum Router), eine für LAN (zu den Clients).

### 2.2 Betriebssystem-Anforderungen

#### Linux (Empfohlen)

- **Distribution:** Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, oder ähnlich
- **Kernel:** 5.4+ (mit iptables/nftables-Support)
- **Python:** 3.10 oder neuer
- **systemd:** Für automatischen Start als Dienst
- **Root-Rechte:** Für Scapy-Paketerfassung und Firewall-Manipulation

#### Windows

- **Version:** Windows 10/11 oder Windows Server 2019+
- **Python:** 3.10+ (von python.org)
- **Npcap:** Packet Capture Treiber (https://npcap.com)
- **Administrator-Rechte:** Erforderlich für Paketerfassung und Firewall

> ⚠️ **WARNUNG:** Windows unterstützt KEINEN Bridge-Mode! Windows kann nur im Host-Modus betrieben werden.

#### macOS

- **Version:** macOS 11 Big Sur oder neuer
- **Python:** 3.10+ (via Homebrew: `brew install python@3.11`)
- **Xcode Command Line Tools:** `xcode-select --install`
- **sudo-Rechte:** Für pfctl-Firewall-Steuerung

---

## 3. Installation

### 3.1 Linux-Installation (Automatisch)

Die empfohlene Methode für Linux ist das automatische Installationsskript, das NFM als systemd-Dienst mit Zwei-Prozess-Architektur (Monitor als root, Web-Interface unprivilegiert) einrichtet.

#### Schritt 1: Download & Entpacken

```bash
# Download der V3_9_1_fixed.zip
unzip V3_9_1_fixed.zip
cd V3.9.1/
```

#### Schritt 2: Installation ausführen

```bash
sudo bash install.sh
```

Das Skript führt folgende Schritte automatisch durch:

1. Legt System-User 'netfiremon' an (kein Login, unprivilegiert)
2. Erstellt `/opt/netfiremon/` mit korrekten Berechtigungen
3. Installiert Python-Virtual-Environment (`.venv`)
4. Installiert alle Abhängigkeiten (scapy, flask, gunicorn, etc.)
5. Registriert systemd-Dienste (netfiremon + netfiremon-web)
6. Startet Setup-Wizard für Erst-Konfiguration
7. Startet beide Dienste automatisch

#### Schritt 3: Setup-Wizard

Der Setup-Wizard führt Sie durch folgende Einstellungen:

- **Web-Interface-Passwort:** Mindestens 8 Zeichen, wird mit scrypt gehasht
- **Netzwerk-Interface:** Wählen Sie das Interface für die Überwachung (z.B. eth0, br0)
- **Firewall-Modus:** monitor (nur beobachten), confirm (fragen), oder auto (automatisch blockieren)
- **E-Mail-Benachrichtigungen:** Optional: SMTP-Server, Absender, Empfänger

#### Schritt 4: Dienst-Kontrolle

Nach erfolgreicher Installation steuern Sie NFM über systemd:

```bash
# Status prüfen
sudo systemctl status netfiremon netfiremon-web

# Dienste neu starten
sudo systemctl restart netfiremon netfiremon-web

# Logs live verfolgen
sudo journalctl -u netfiremon -f
sudo journalctl -u netfiremon-web -f

# Dienste stoppen
sudo systemctl stop netfiremon netfiremon-web
```

> ✅ **ERFOLG:** Das Web-Interface ist nun unter `https://<IP-Adresse>:5443` erreichbar!

### 3.2 Windows-Installation

#### Schritt 1: Npcap installieren

> ⚠️ **WARNUNG:** Ohne Npcap kann NFM unter Windows KEINE Pakete erfassen! Npcap ist zwingend erforderlich.

1. Gehen Sie zu https://npcap.com/#download
2. Laden Sie den neuesten Installer herunter
3. Führen Sie den Installer mit Administrator-Rechten aus
4. **Wichtig:** Aktivieren Sie die Option 'WinPcap API-compatible Mode'

#### Schritt 2: Python installieren

1. Laden Sie Python 3.11+ von https://python.org herunter
2. **Wichtig:** Aktivieren Sie 'Add Python to PATH' während der Installation!

#### Schritt 3: NFM entpacken und starten

```powershell
# Im PowerShell oder CMD (als Administrator):
cd C:\NFM
python netfiremon_web.py
```

NFM installiert beim ersten Start automatisch alle Python-Abhängigkeiten und startet den Setup-Wizard.

> ⚠️ **Windows-Firewall-Warnung:** Beim ersten Start fragt Windows, ob NFM Netzwerkzugriff erhalten darf. Klicken Sie auf 'Zugriff zulassen' (sowohl für private als auch öffentliche Netzwerke).

### 3.3 macOS-Installation

#### Schritt 1: Homebrew & Python

```bash
# Homebrew installieren (falls noch nicht vorhanden)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Python 3.11 installieren
brew install python@3.11
```

#### Schritt 2: Xcode Command Line Tools

```bash
xcode-select --install
```

#### Schritt 3: NFM starten

```bash
cd ~/NFM
sudo python3 netfiremon_web.py
```

> ℹ️ **INFO:** macOS benötigt sudo für die Paketerfassung (Scapy) und pfctl-Firewall-Zugriff.

---

## 4. Dedizierte IPS-Box (Bridge-Mode Setup)

Dies ist die professionelle Enterprise-Lösung: NFM läuft auf einer dedizierten Linux-Box als transparente Netzwerkbrücke zwischen Ihrem Router und dem internen Netzwerk. Der GESAMTE Traffic Ihres Netzwerks fließt durch die IPS-Box und wird analysiert.

> ✅ **VORTEIL:** Schutz für ALLE Geräte im Netzwerk mit EINER zentralen Box. Keine Software-Installation auf Clients nötig!

### 4.1 Netzwerk-Topologie

**Klassische Topologie:**

```
Internet ➜ Router (mit NAT/DHCP) ➜ Switch ➜ PCs
```

**Bridge-Mode-Topologie mit NFM:**

```
Internet ➜ Router (PPPoE, NAT, DHCP)
           ↓
      [ NFM-Box ]  ← Bridge: eth0 (WAN) ↔ eth1 (LAN)
           ↓
    Switch / Fritzbox (nur WLAN-AP)
           ↓
    20 PCs / Clients
```

> ⚠️ **KRITISCH:** In dieser Topologie macht der ROUTER das NAT/DHCP, die Fritzbox ist nur noch ein Switch/WLAN-AP (kein Router-Modus!), und die NFM-Box ist transparent dazwischen!

### 4.2 Hardware-Anforderungen für Bridge-Box

| Komponente | Empfehlung |
|------------|------------|
| **CPU** | Intel i5/i7 oder AMD Ryzen 5/7, mind. 4 Kerne @ 3+ GHz |
| **RAM** | 8–16 GB (je nach Netzwerkgröße) |
| **Netzwerkkarten** | **2x Gigabit Ethernet (Intel I210/I350 empfohlen)** |
| **Festplatte** | 128 GB SSD (System) + 500 GB HDD (Logs, optional) |
| **Betriebssystem** | Ubuntu Server 22.04 LTS oder Debian 12 |

> ℹ️ **TIPP:** Empfohlene Hardware: Mini-PC wie Intel NUC, Lenovo ThinkCentre Tiny, oder HP EliteDesk Mini mit zusätzlicher USB-zu-Ethernet-Karte für das zweite Interface.

### 4.3 Linux-Bridge-Konfiguration

Damit die NFM-Box als transparente Brücke arbeitet, müssen Sie die beiden Netzwerkkarten (eth0 = WAN, eth1 = LAN) zu einer Netzwerk-Bridge (br0) zusammenfassen.

#### Schritt 1: Netzwerk-Interfaces identifizieren

```bash
ip link show
```

Notieren Sie die Namen der beiden Netzwerkkarten, z.B.:

- **eth0** → Verbindung zum Router (WAN)
- **eth1** → Verbindung zum Switch/Fritzbox (LAN)

#### Schritt 2: Bridge-Paket installieren

```bash
sudo apt update
sudo apt install bridge-utils
```

#### Schritt 3: Netplan-Konfiguration (Ubuntu/Debian)

Bearbeiten Sie `/etc/netplan/01-netcfg.yaml` (Ubuntu) oder `/etc/network/interfaces` (Debian):

```yaml
# /etc/netplan/01-netcfg.yaml (Ubuntu 22.04+)
network:
  version: 2
  renderer: networkd

  ethernets:
    eth0:
      dhcp4: no
      dhcp6: no
    eth1:
      dhcp4: no
      dhcp6: no

  bridges:
    br0:
      interfaces: [eth0, eth1]
      dhcp4: no
      addresses:
        - 192.168.1.254/24  # Management-IP für SSH/Web
      routes:
        - to: 0.0.0.0/0
          via: 192.168.1.1  # Gateway (Router)
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

> ⚠️ **WICHTIG:** Die Management-IP (192.168.1.254) muss im SELBEN Subnetz wie Ihre Clients liegen, aber eine freie IP sein! Prüfen Sie Ihr Netzwerk vorher.

#### Schritt 4: Konfiguration anwenden

```bash
sudo netplan apply
```

Prüfen Sie, ob die Bridge aktiv ist:

```bash
ip addr show br0
brctl show
```

> ✅ **ERFOLG:** Wenn br0 aktiv ist und beide Interfaces (eth0, eth1) als members angezeigt werden, ist die Bridge erfolgreich konfiguriert!

### 4.4 br_netfilter aktivieren (KRITISCH!)

Dies ist der WICHTIGSTE Schritt! Standardmäßig ignoriert Linux iptables-Regeln für Traffic, der nur durch eine Bridge fließt. NFM würde dann zwar Alarme auslösen, aber NICHTS blockieren!

> ⚠️ **WARNUNG:** Ohne br_netfilter funktioniert die Firewall-Blockierung im Bridge-Mode NICHT!

#### Schritt 1: Kernel-Modul laden

```bash
sudo modprobe br_netfilter
```

#### Schritt 2: iptables für Bridge aktivieren

```bash
sudo sysctl -w net.bridge.bridge-nf-call-iptables=1
sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1
```

#### Schritt 3: Dauerhaft aktivieren

```bash
# Modul beim Boot laden
echo 'br_netfilter' | sudo tee -a /etc/modules

# sysctl-Einstellungen permanent
sudo nano /etc/sysctl.d/99-bridge-nf.conf
```

Fügen Sie folgende Zeilen hinzu:

```
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
```

Speichern und neu laden:

```bash
sudo sysctl -p /etc/sysctl.d/99-bridge-nf.conf
```

#### Schritt 4: Verifizierung

```bash
sysctl net.bridge.bridge-nf-call-iptables
# Ausgabe sollte sein: net.bridge.bridge-nf-call-iptables = 1
```

> ✅ **ERFOLG:** Perfekt! Die Bridge ist jetzt vollständig konfiguriert und iptables-Regeln greifen auf durchfließenden Traffic. NFM kann jetzt IPs blockieren!

### 4.5 NFM im Bridge-Mode installieren

Folgen Sie nun der normalen Linux-Installation (Kapitel 3.1), mit einem wichtigen Unterschied:

> ⚠️ **WICHTIG:** Beim Setup-Wizard wählen Sie als Interface: **br0** (nicht eth0 oder eth1!)

```bash
sudo bash install.sh
# Im Setup-Wizard:
# Interface: br0
# Firewall-Modus: auto (für automatische Blockierung)
```

#### Whitelist-Konfiguration

SEHR WICHTIG: Fügen Sie vor dem ersten Produktivbetrieb Ihre eigene Management-IP zur Whitelist hinzu, sonst könnten Sie sich selbst aussperren!

```bash
# Im Web-Interface: https://192.168.1.254:5443
# → Whitelist → Hinzufügen: 192.168.1.254
# → Whitelist → Hinzufügen: 192.168.1.0/24 (Ihr gesamtes LAN)
```

> ✅ **ERFOLG:** Ihr Netzwerk ist jetzt vollständig geschützt! Jeder Traffic fließt durch die IPS-Box und wird in Echtzeit analysiert.

---

## 5. Konfiguration & Einstellungen

### 5.1 Firewall-Modi

NFM unterstützt drei Firewall-Modi, die das Verhalten bei erkannten Bedrohungen steuern:

| Modus | Verhalten |
|-------|-----------|
| **monitor** | Nur Beobachtung. NFM erkennt Angriffe und schreibt Alarme, blockiert aber nichts. Ideal für Test-Phase und Baseline-Ermittlung. |
| **confirm** | Manuelle Bestätigung. Bei Alarmen fragt NFM, ob blockiert werden soll. Sie entscheiden über jeden Block einzeln. Nur im Terminal-Modus verfügbar. |
| **auto** | Automatische Blockierung. NFM blockiert erkannte Bedrohungen sofort ohne Rückfrage. Empfohlen für Produktivbetrieb mit gut konfigurierter Whitelist. |

> ⚠️ **EMPFEHLUNG:** Starten Sie im 'monitor'-Modus für 1-2 Wochen, um False Positives zu identifizieren und die Whitelist zu pflegen. Danach wechseln Sie auf 'auto'.

### 5.2 Threshold (Schwellwert) richtig einstellen

Der Threshold bestimmt, ab welcher Abweichung von der Baseline ein Alarm ausgelöst wird. Der Wert ist in Prozent angegeben.

- **Threshold = 30%:** Alarm bei 30% mehr Traffic als Baseline (sehr empfindlich)
- **Threshold = 50%:** Alarm bei 50% mehr Traffic (Standard, ausgewogen)
- **Threshold = 100%:** Alarm erst bei doppeltem Traffic (weniger empfindlich)

> ℹ️ **INFO:** Die Baseline wird automatisch über 5 Minuten berechnet. Sie stellt den 'normalen' Traffic dar. NFM löst nur dann Alarm aus, wenn der aktuelle Traffic den Threshold überschreitet.

#### Empfohlene Threshold-Werte

| Szenario | Threshold | Begründung |
|----------|-----------|------------|
| Einzelner PC/Server | 30–40% | Stabiler Traffic, wenig Varianz |
| Bridge-Mode (< 10 Clients) | 50–60% | Moderate Varianz |
| Bridge-Mode (> 20 Clients) | 80–100% | Hohe Varianz, Video-Streaming |

---

## 6. BPF-Filter (Berkeley Packet Filter)

BPF-Filter sind der Schlüssel zur Performance-Optimierung von NFM. Sie legen fest, WELCHE Pakete von Scapy erfasst und analysiert werden sollen.

> ⚠️ **WARNUNG:** Ohne BPF-Filter analysiert NFM JEDEN Frame - bei 20+ Clients und Gigabit-Verbindungen kann das 100.000+ Pakete pro Sekunde bedeuten. Das überfordert jede CPU!

### 6.1 Grundlagen

BPF-Filter werden DIREKT in der Netzwerkkarte (oder im Kernel) angewendet, BEVOR Pakete an NFM weitergereicht werden. Nicht-matching Pakete werden sofort verworfen.

#### Syntax-Grundlagen

```bash
# IP-Protokoll (erfasst IPv4 und IPv6)
ip or ip6

# Nur TCP-Traffic
tcp

# Nur UDP
udp

# Nur ICMP (Ping)
icmp

# Kombinationen mit 'and', 'or', 'not'
tcp and port 80
tcp or udp
not port 443
```

### 6.2 Standard-Filter (Empfohlen)

#### Host-Modus (Einzelner PC/Server)

```
ip or ip6
```

**Bedeutung:** Erfasst allen IPv4- und IPv6-Traffic. Einfach und umfassend.

> ✅ **PERFEKT FÜR:** Einzelne Hosts, Server, Workstations

#### Bridge-Modus - Basis (< 10 Clients)

```
tcp[tcpflags] & (tcp-syn) != 0 or icmp or udp
```

**Bedeutung (Schritt für Schritt):**

- `tcp[tcpflags] & (tcp-syn) != 0`: Nur TCP-Pakete mit gesetztem SYN-Flag (neue Verbindungen)
- `or icmp`: Zusätzlich alle ICMP-Pakete (Ping, etc.)
- `or udp`: Zusätzlich alle UDP-Pakete (DNS, DHCP, VoIP)

> ℹ️ **INFO:** Dieser Filter reduziert die Last erheblich: Statt jeden TCP-Frame zu analysieren, wird nur der ERSTE Frame einer TCP-Verbindung erfasst (SYN). Port-Scans und neue Verbindungen werden erkannt, aber der Datenverkehr etablierter Verbindungen ignoriert.

> ✅ **PERFEKT FÜR:** 5-15 Clients, kleine Büro-Netzwerke

#### Bridge-Modus - Optimiert (20+ Clients)

```
tcp[tcpflags] & (tcp-syn) != 0 or icmp or (udp and not port 443 and not port 80)
```

**Bedeutung:**

- `tcp[tcpflags] & (tcp-syn) != 0`: Wie oben - nur neue TCP-Verbindungen
- `or icmp`: Alle ICMP-Pakete
- `or (udp and not port 443 and not port 80)`: UDP-Pakete, ABER NICHT auf Port 443 (HTTPS über QUIC) und nicht Port 80

> ⚠️ **WARUM PORT 443/80 AUSSCHLIESSEN?** Moderne Browser verwenden QUIC (UDP Port 443) für HTTPS-Verbindungen. Das erzeugt bei Video-Streaming MASSIVEN UDP-Traffic. Durch den Ausschluss wird die CPU-Last um 60-80% reduziert!

> ✅ **PERFEKT FÜR:** 20+ Clients, Netzwerke mit viel Video/Streaming

### 6.3 Erweiterte BPF-Filter-Beispiele

#### Nur eingehenden Traffic (Inbound)

```
(tcp[tcpflags] & (tcp-syn) != 0) and dst host 192.168.1.0/24
```

Erfasst nur neue TCP-Verbindungen, die AN Ihr Netzwerk (192.168.1.0/24) gerichtet sind. Ausgehender Traffic wird ignoriert.

#### Nur bestimmte Ports überwachen

```
tcp and (port 22 or port 3389 or port 445)
```

Überwacht nur SSH (22), RDP (3389) und SMB (445) - typische Angriffsziele.

#### Ausschluss interner Traffic

```
ip and not (src net 192.168.1.0/24 and dst net 192.168.1.0/24)
```

Ignoriert Traffic zwischen internen Hosts (192.168.1.x → 192.168.1.y). Nur Traffic von/zu externen IPs wird analysiert.

### 6.4 BPF-Filter im NFM setzen

#### Methode 1: Über das Web-Interface

1. Öffnen Sie `https://<IP>:5443`
2. Klicken Sie auf 'Konfiguration'
3. Scrollen Sie zu 'BPF Filter'
4. Tragen Sie Ihren Filter ein, z.B.:
   ```
   tcp[tcpflags] & (tcp-syn) != 0 or icmp or udp
   ```
5. Klicken Sie 'Speichern'
6. Starten Sie NFM neu: `sudo systemctl restart netfiremon`

#### Methode 2: Direkt in der Konfigurationsdatei

```bash
sudo nano /opt/netfiremon/data/net_fire_monitor_config.json
```

Suchen Sie die Zeile `"bpf_filter"` und ändern Sie den Wert:

```json
{
  "bpf_filter": "tcp[tcpflags] & (tcp-syn) != 0 or icmp or udp",
  "interface": "br0",
  ...
}
```

Speichern (Strg+O) und schließen (Strg+X), dann NFM neu starten.

### 6.5 BPF-Filter testen & validieren

Bevor Sie einen BPF-Filter produktiv einsetzen, sollten Sie ihn mit tcpdump testen:

```bash
# Testen Sie Ihren Filter mit tcpdump:
sudo tcpdump -i br0 "tcp[tcpflags] & (tcp-syn) != 0 or icmp" -c 10

# Bedeutung:
#   -i br0        → auf Interface br0 lauschen
#   -c 10         → nur 10 Pakete erfassen, dann stoppen
#   Der Rest ist der BPF-Filter
```

Wenn tcpdump Pakete anzeigt und keine Fehlermeldung kommt, ist der Filter syntaktisch korrekt.

> ✅ **TIPP:** Lassen Sie tcpdump 1 Minute laufen und zählen Sie die Pakete. Bei > 1000 pps sollten Sie den Filter verschärfen!

---

## 7. Betrieb & Bedienung

### 7.1 Web-Interface

Das Web-Interface ist über HTTPS erreichbar und bietet eine grafische Oberfläche zur Überwachung und Steuerung von NFM.

```
https://<IP-Adresse>:5443
```

> ℹ️ **INFO:** Die Browser-Warnung beim ersten Aufruf ist normal - das Zertifikat ist selbst-signiert. Klicken Sie auf 'Erweitert' → 'Risiko akzeptieren'.

#### Dashboard-Übersicht

**Das Dashboard zeigt in Echtzeit:**

- **Live-Statistiken:** Aktuelle PPS/BPS, Baseline, Threshold, Alarm-Zähler
- **PPS-Graph:** Packets-per-Second über die letzten 60 Sekunden
- **Top Talkers:** Die 10 aktivsten IPs mit Hostname und Geo-Lokalisierung
- **Protokoll-Verteilung:** TCP / UDP / ICMP / Other als Balkendiagramm
- **Top Ports:** Die 10 meistgenutzten Ports mit Service-Namen
- **Letzte Pakete:** Live-Stream der erfassten Pakete

#### Alarme-Seite

Zeigt alle ausgelösten Alarme mit Zeitstempel, IP-Adresse und Grund. Pro Alarm können Sie direkt:

- **Blockieren:** IP sofort sperren
- **Whitelist:** IP zur Whitelist hinzufügen (nie wieder blockiert)
- **Blacklist:** IP permanent auf die Blacklist setzen

#### Whitelist & Blacklist

Hier verwalten Sie Ihre IP-Listen:

- **Whitelist:** IPs die NIEMALS blockiert werden (auch nicht durch Threat Intel)
- **Blacklist:** IPs die IMMER blockiert werden

> ⚠️ **WICHTIG:** Fügen Sie Ihre eigene Management-IP (SSH/Web-Zugriff) zur Whitelist hinzu, BEVOR Sie den auto-Modus aktivieren!

#### Firewall-Regeln

Erstellen Sie benutzerdefinierte Firewall-Regeln nach Port, Protokoll und Aktion:

```
# Beispiel: Blockiere alle eingehenden Verbindungen auf Port 3389 (RDP)
Protokoll: tcp
Port: 3389
Aktion: block
Kommentar: RDP nicht erlaubt
```

### 7.2 Terminal-Dashboard

Das Terminal-Dashboard bietet eine Rich-basierte Live-Ansicht direkt im Terminal. Perfekt für SSH-Sessions oder Konsolen-Zugriff.

```bash
sudo python3 netfiremon_terminal.py
```

**Features:**

- Live-PPS-Graph mit ASCII-Art
- Farbcodierte Statistiken
- Top Talkers mit Geo-IP
- Letzte Alarme
- Threat-Intel-Zähler

### 7.3 E-Mail-Benachrichtigungen einrichten

NFM kann bei jedem Alarm eine HTML-E-Mail mit vollständiger IP-Analyse versenden.

#### SMTP-Konfiguration

Im Web-Interface → Konfiguration:

| Parameter | Beispiel |
|-----------|----------|
| E-Mail aktiviert | true |
| SMTP-Server | smtp.gmail.com |
| SMTP-Port | 587 (TLS) oder 465 (SSL) |
| Absender | nfm@example.com |
| Empfänger | admin@example.com |
| Benutzername | nfm@example.com |

> ⚠️ **Gmail-Nutzer:** Sie benötigen ein App-Passwort, NICHT Ihr normales Gmail-Passwort! Erstellen Sie es unter: https://myaccount.google.com/apppasswords

#### E-Mail-Passwort sicher setzen

```bash
# Methode 1: Umgebungsvariable (empfohlen für systemd)
sudo nano /etc/systemd/system/netfiremon.service

# Fügen Sie unter [Service] hinzu:
Environment="NFM_EMAIL_PASSWORD=IhrAppPasswort123"

# Methode 2: Datei (für manuellen Start)
echo 'IhrAppPasswort123' | sudo tee /opt/netfiremon/data/.email_password
sudo chmod 600 /opt/netfiremon/data/.email_password
```

---

## 8. Best Practices & Sicherheit

### 8.1 OS-Hardening für die IPS-Box

Eine dedizierte IPS-Box sollte minimal und gehärtet sein:

#### 1. Minimale Installation

```bash
# Ubuntu Server ohne GUI installieren
# NUR diese Pakete zusätzlich:
sudo apt install openssh-server fail2ban ufw htop
```

#### 2. SSH absichern

```bash
sudo nano /etc/ssh/sshd_config

# Ändern Sie:
PermitRootLogin no
PasswordAuthentication no  # Nur Key-basiert
Port 2222  # Nicht-Standard-Port

sudo systemctl restart sshd
```

#### 3. Firewall auf der Box selbst

```bash
# UFW (Uncomplicated Firewall) für Management-Zugriff
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp  # SSH
sudo ufw allow 5443/tcp  # NFM Web-Interface
sudo ufw enable
```

> ⚠️ **WICHTIG:** Aktivieren Sie UFW NACH dem SSH-Port-Regel, sonst sperren Sie sich aus!

#### 4. Automatische Updates

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

#### 5. fail2ban für SSH

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 8.2 Whitelist-Strategie

Die Whitelist ist Ihre wichtigste Waffe gegen False Positives:

- **Management-IPs:** Ihre eigene IP, SSH-IPs, Admin-Workstations
- **Internes Netz (optional):** 192.168.1.0/24 (verhindert Blockierung interner Hosts)
- **Bekannte Dienste:** Cloud-Provider (AWS, Azure, Google), CDNs (Cloudflare, Akamai)
- **Business-Partner:** IPs von Lieferanten, Kunden, API-Endpunkten

> ⚠️ **WARNUNG:** Whitelisted IPs werden NIEMALS blockiert - auch nicht durch Threat Intelligence! Pflegen Sie Ihre Whitelist sorgfältig.

### 8.3 Monitoring & Wartung

#### Tägliche Checks

```bash
# Status prüfen
sudo systemctl status netfiremon netfiremon-web

# Aktuelle Alarme
tail -100 /opt/netfiremon/data/net_fire_monitor.log | grep WARNING

# Blockierte IPs
sudo iptables -L INPUT -v -n | grep NetFireMon
```

#### Wöchentliche Checks

- Prüfen Sie die Top-Talker auf ungewöhnliche IPs
- Überprüfen Sie neue Alarme in der Alarme-Seite
- Aktualisieren Sie die Threat-Intel-Liste (automatisch)
- Backup der Konfiguration

```bash
sudo cp /opt/netfiremon/data/net_fire_monitor_config.json ~/backup/
```

#### Log-Rotation

NFM rotiert Logs automatisch:

- `net_fire_monitor.log`: 5 MB × 3 Backups
- `firewall.log`: 2 MB × 5 Backups

---

## 9. Troubleshooting

### 9.1 Häufige Probleme

#### Problem: NFM blockiert nichts (Modus = auto)

**Lösung:**

1. Prüfen Sie Root-Rechte: `sudo systemctl status netfiremon`
2. Im Bridge-Mode: Ist br_netfilter aktiv? `sysctl net.bridge.bridge-nf-call-iptables`
3. Prüfen Sie die Firewall-Regeln: `sudo iptables -L -v -n`

#### Problem: Zu viele False Positives

**Lösung:**

1. Erhöhen Sie den Threshold (z.B. von 30% auf 60%)
2. Fügen Sie legitime IPs zur Whitelist hinzu
3. Optimieren Sie den BPF-Filter (zu viel Traffic erfasst?)
4. Wechseln Sie in den 'confirm'-Modus für manuelle Kontrolle

#### Problem: Hohe CPU-Last

**Lösung:**

1. Verschärfen Sie den BPF-Filter (nur SYN-Pakete erfassen)
2. Erhöhen Sie `max_tracked_ips` in der Konfiguration
3. Deaktivieren Sie Geo-IP (optional)
4. Upgrade auf stärkere Hardware

#### Problem: Web-Interface nicht erreichbar

**Lösung:**

```bash
# Prüfen Sie den Web-Dienst
sudo systemctl status netfiremon-web

# Prüfen Sie die Logs
sudo journalctl -u netfiremon-web -n 50

# Prüfen Sie die Firewall
sudo ufw status
sudo ufw allow 5443/tcp
```

#### Problem: Ich habe mich selbst ausgesperrt

**Lösung:**

```bash
# Physischen Zugang zur Box herstellen (Tastatur + Monitor)
# Oder: Reboot per Remote-Hands

# Beim Boot: NFM stoppen
sudo systemctl stop netfiremon

# Alle NFM-Firewall-Regeln entfernen
sudo iptables -F
sudo iptables -X

# Oder: spezifisch Ihre IP freigeben
sudo iptables -D INPUT -s IHRE.IP.ADRESSE -j DROP
```

### 9.2 Log-Analyse

#### Monitor-Log analysieren

```bash
# Letzte 100 Zeilen
tail -100 /opt/netfiremon/data/net_fire_monitor.log

# Nur Alarme
grep WARNING /opt/netfiremon/data/net_fire_monitor.log | tail -50

# Nur Threat-Intel-Blocks
grep 'threat_intel' /opt/netfiremon/data/net_fire_monitor.log
```

#### Firewall-Log analysieren

```bash
# Alle blockierten IPs heute
grep BLOCKED /opt/netfiremon/data/firewall.log | grep $(date +%Y-%m-%d)

# Welche IP wurde am häufigsten blockiert?
grep BLOCKED /opt/netfiremon/data/firewall.log | awk '{print $4}' | sort | uniq -c | sort -rn | head -10
```

---

## 10. Anhang

### 10.1 Schnellreferenz: Wichtigste Befehle

| Aktion | Befehl |
|--------|--------|
| NFM installieren | `sudo bash install.sh` |
| NFM starten | `sudo systemctl start netfiremon` |
| NFM stoppen | `sudo systemctl stop netfiremon` |
| Status prüfen | `sudo systemctl status netfiremon` |
| Logs live | `sudo journalctl -u netfiremon -f` |
| Web-Interface | `https://<IP>:5443` |
| Bridge-Status | `brctl show` |
| Firewall-Regeln | `sudo iptables -L -v -n` |
| Konfiguration bearbeiten | Web-Interface → Konfiguration |

### 10.2 Weitere Ressourcen

- **GitHub Repository:** (falls verfügbar) - Für Updates und Issues
- **BPF-Filter Dokumentation:** https://www.tcpdump.org/manpages/pcap-filter.7.html
- **iptables Tutorial:** https://www.netfilter.org/documentation/
- **Scapy Dokumentation:** https://scapy.readthedocs.io/

---

**Ende der Bedienungsanleitung**

*Net-Fire-Monitor v3.9 © 2023–2026 Manuel Person – Innobytix-IT*
