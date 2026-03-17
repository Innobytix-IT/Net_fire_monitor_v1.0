"""
╔══════════════════════════════════════════════════════════════╗
║     NET-FIRE-MONITOR  v3.9  –  Terminal-Modus               ║
║     Startet nur das Terminal-Dashboard (kein Web-Server)    ║
╚══════════════════════════════════════════════════════════════╝

Verwendung:
  sudo python netfiremon_terminal.py           # Interaktiv
  sudo python netfiremon_terminal.py --auto    # Für systemd / Autostart
  sudo python netfiremon_terminal.py --setup   # Setup-Assistent erzwingen
"""

from __future__ import annotations
import os, platform, sys, time, threading
from pathlib import Path

# ── Frühzeitiger Setup-Check ────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from core import (
    SETUP_DONE_FILE, first_run_setup,
    Config, CONFIG_FILE,
    FirewallEngine, EmailNotifier, ThreatIntelManager, RuleEngine, SyslogExporter,
    NetworkMonitor,
    save_state, load_state,
    restore_on_startup,
    _fmt_bps, send_notification,
    PLYER_OK, GEOIP_DB,
    geo_lookup, geo_color, is_private_ip, resolve_hostname,
    _dns_cache, _dns_lock,
)
import core as _core

if not SETUP_DONE_FILE.exists():
    first_run_setup()
    if platform.system() == "Windows":
        import subprocess as _sp
        sys.exit(_sp.call([sys.executable] + sys.argv))
    else:
        os.execv(sys.executable, [sys.executable] + sys.argv)

# ── Drittanbieter ────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6
    from scapy.layers.inet import TCP, UDP, ICMP
except ImportError:
    sys.exit("❌  Scapy nicht gefunden. Bitte: pip install scapy")

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.rule import Rule
    from rich.columns import Columns
except ImportError:
    sys.exit("❌  Rich nicht gefunden. Bitte: pip install rich")

console = Console()

# ════════════════════════════════════════════════════════════════════════════
# DASHBOARD-RENDERING
# ════════════════════════════════════════════════════════════════════════════

COLORS = {"TCP":"cyan","UDP":"green","ICMP":"yellow","OTHER":"dim"}


def make_header(cfg: Config) -> Panel:
    from datetime import datetime
    mode_colors = {"monitor":"green","confirm":"yellow","auto":"red"}
    mode_labels = {"monitor":"👁  MONITOR","confirm":"⚡ CONFIRM","auto":"🔥 AUTO-BLOCK"}
    ti = _core._threat_intel
    ti_count = ti.get_count() if ti else 0
    txt = Text()
    txt.append("NET-FIRE-MONITOR  v3.9", style="bold white on blue")
    txt.append("  │  ", style="dim")
    txt.append(f"Interface: {cfg.interface or 'alle'}", style="yellow")
    txt.append("  │  ", style="dim")
    txt.append(f"Modus: {mode_labels.get(cfg.firewall_mode,'?')}",
               style=f"bold {mode_colors.get(cfg.firewall_mode,'white')}")
    txt.append("  │  ", style="dim")
    txt.append(f"Threat-Intel: {ti_count:,} IPs", style="magenta")
    txt.append("  │  ", style="dim")
    txt.append(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"), style="green")
    return Panel(txt, box=box.HORIZONTALS, style="bold blue")


def make_stats_panel(mon: NetworkMonitor) -> Panel:
    pps_now = mon.pps_history[-1] if mon.pps_history else 0.0
    bps_now = mon.bps_history[-1] if mon.bps_history else 0.0
    limit   = mon.baseline_pps * (1 + mon.cfg.threshold / 100)
    color   = "green" if pps_now <= limit * 0.8 else ("yellow" if pps_now <= limit else "red")
    grid = Table.grid(padding=(0,2))
    grid.add_column(justify="right", style="bold")
    grid.add_column()
    grid.add_row("Aktuell:",       f"[{color}]{pps_now:.2f} pps  |  {_fmt_bps(bps_now)}[/{color}]")
    grid.add_row("Baseline:",      f"{mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}")
    grid.add_row("Schwellenwert:", f"{limit:.2f} pps  (+{mon.cfg.threshold}%)")
    grid.add_row("Alarme gesamt:", f"[red]{mon.alert_count}[/red]")
    return Panel(grid, title="[bold]📊  Live-Statistik[/bold]", border_style=color)


def make_sparkline(history, width: int = 40) -> str:
    if not history: return "–"
    vals = list(history)[-width:]
    mx   = max(vals) or 1
    chars = " ▁▂▃▄▅▆▇█"
    return "".join(chars[min(8, int(v/mx*8))] for v in vals)


def make_graph_panel(mon: NetworkMonitor) -> Panel:
    grid = Table.grid(padding=(0,1))
    grid.add_column(style="bold", width=8)
    grid.add_column()
    grid.add_row("pps:", f"[green]{make_sparkline(mon.pps_history)}[/green]")
    grid.add_row("B/s:", f"[cyan]{make_sparkline(mon.bps_history)}[/cyan]")
    return Panel(grid, title="[bold]📈  Verlauf (letzte 60 Messungen)[/bold]", border_style="blue")


def make_proto_panel(mon: NetworkMonitor) -> Panel:
    stats = mon.get_proto_stats()
    total = sum(stats.values()) or 1
    tbl   = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    tbl.add_column(width=6, style="bold")
    tbl.add_column(width=8, justify="right")
    tbl.add_column(width=20)
    for proto in ("TCP","UDP","ICMP","OTHER"):
        cnt = stats.get(proto, 0)
        pct = cnt / total * 100
        bar = "█" * int(pct / 5)
        col = COLORS.get(proto, "white")
        tbl.add_row(f"[{col}]{proto}[/{col}]", f"{cnt:,}",
                    f"[{col}]{bar:<20}[/{col}] {pct:.1f}%")
    return Panel(tbl, title="[bold]🔌  Protokolle[/bold]", border_style="magenta")


def make_top_talkers_panel(mon: NetworkMonitor, resolve: bool = False) -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("IP-Adresse",  style="cyan",  min_width=16)
    tbl.add_column("Hostname",    style="dim",   min_width=20)
    tbl.add_column("Pakete",      justify="right")
    tbl.add_column("Typ",         justify="center")
    for ip, cnt in mon.get_top_talkers():
        host = resolve_hostname(ip) if resolve else "–"
        priv = "🏠" if is_private_ip(ip) else "🌐"
        tbl.add_row(ip, host, str(cnt), priv)
    return Panel(tbl, title="[bold]🔝  Top-Talker[/bold]", border_style="cyan")


def make_top_ports_panel(mon: NetworkMonitor) -> Panel:
    WK = {20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
          80:"HTTP",443:"HTTPS",3306:"MySQL",3389:"RDP",8080:"HTTP-Alt"}
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
    tbl.add_column("Port",   justify="right")
    tbl.add_column("Dienst", style="green")
    tbl.add_column("Pakete", justify="right")
    for port, cnt in mon.get_top_ports():
        tbl.add_row(str(port), WK.get(port,"–"), str(cnt))
    return Panel(tbl, title="[bold]🔒  Top-Ports[/bold]", border_style="green")


def make_recent_packets_panel(mon: NetworkMonitor) -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
    tbl.add_column("Zeit",   style="dim",     width=10)
    tbl.add_column("Land",   style="magenta", width=15, no_wrap=True)
    tbl.add_column("Src-IP", style="cyan",    min_width=15)
    tbl.add_column("→",      width=2)
    tbl.add_column("Dst-IP", style="yellow",  min_width=15)
    tbl.add_column("Proto",  width=6)
    tbl.add_column("Port",   width=6, justify="right")
    tbl.add_column("Größe",  width=7, justify="right")
    tbl.add_column("Flags",  width=6)
    with mon._lock:
        pkts = list(mon.recent_packets)[-12:]
    for p in reversed(pkts):
        col = COLORS.get(p.protocol, "white")
        if is_private_ip(p.src_ip):
            country_display = "[dim]LAN[/dim]"
        else:
            c     = geo_lookup(p.src_ip)
            color = geo_color(c.split(", ")[-1] if ", " in c else c)
            country_display = f"[{color}]{c}[/{color}]"
        tbl.add_row(p.timestamp, country_display, p.src_ip, "→", p.dst_ip,
                    f"[{col}]{p.protocol}[/{col}]", str(p.dst_port), f"{p.size} B", p.flags or "–")
    return Panel(tbl, title="[bold]📦  Letzte Pakete[/bold]", border_style="white")


def make_alerts_panel(mon: NetworkMonitor) -> Panel:
    with mon._lock:
        alerts = list(mon.alerts)[:6]
    if not alerts:
        return Panel(Text("Keine Alarme  ✅", style="green"),
                     title=f"[bold red]🚨  Alarme (0)[/bold red]", border_style="red")
    content = Text()
    for a in alerts:
        content.append(a + "\n", style="red")
    return Panel(content, title=f"[bold red]🚨  Alarme ({mon.alert_count})[/bold red]", border_style="red")


def make_blocked_panel() -> Panel:
    fw = _core._firewall
    if not fw or not fw.blocked_ips:
        return Panel(Text("Keine blockierten IPs  ✅", style="green"),
                     title="[bold]🛡️  Geblockte IPs[/bold]", border_style="green")
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold red")
    tbl.add_column("IP-Adresse", style="red")
    tbl.add_column("Hostname",   style="dim")
    tbl.add_column("Status",     justify="center")
    with fw._lock:
        blocked = list(fw.blocked_ips)
    for ip in blocked[:10]:
        with _dns_lock:
            host = _dns_cache.get(ip, "–")
        tbl.add_row(ip, host, "🚫 BLOCKED")
    return Panel(tbl, title=f"[bold red]🛡️  Geblockte IPs ({len(blocked)})[/bold red]", border_style="red")


def build_layout(mon: NetworkMonitor, cfg: Config) -> Panel:
    top_row = Table.grid(expand=True, padding=(0,1))
    top_row.add_column(ratio=1); top_row.add_column(ratio=1); top_row.add_column(ratio=1)
    top_row.add_row(make_stats_panel(mon), make_proto_panel(mon), make_alerts_panel(mon))
    mid_row = Table.grid(expand=True, padding=(0,1))
    mid_row.add_column(ratio=1); mid_row.add_column(ratio=1)
    mid_row.add_row(make_top_talkers_panel(mon, resolve=cfg.resolve_dns), make_top_ports_panel(mon))
    layout = Table.grid(expand=True)
    layout.add_column()
    layout.add_row(make_header(cfg))
    layout.add_row(make_graph_panel(mon))
    layout.add_row(top_row)
    layout.add_row(mid_row)
    layout.add_row(make_blocked_panel())
    layout.add_row(make_recent_packets_panel(mon))
    return Panel(layout, box=box.HEAVY, border_style="blue", padding=0)


# ════════════════════════════════════════════════════════════════════════════
# SETUP-WIZARD
# ════════════════════════════════════════════════════════════════════════════

def setup_wizard(cfg: Config) -> Config:
    console.print(Rule("[bold blue]NET-FIRE-MONITOR  v3.9  –  Einrichtungsassistent[/bold blue]"))
    cfg.threshold        = IntPrompt.ask("Sensitiv-Schwellenwert in % [5–25]", default=cfg.threshold)
    cfg.monitor_interval = IntPrompt.ask("Messintervall in Sekunden", default=cfg.monitor_interval)
    cfg.resolve_dns      = Confirm.ask("DNS-Auflösung?", default=cfg.resolve_dns)
    cfg.detect_portscan  = Confirm.ask("Port-Scan-Erkennung?", default=cfg.detect_portscan)

    console.print()
    console.print(Rule("[bold yellow]Firewall-Modus[/bold yellow]"))
    console.print("  [green]monitor[/green]  – nur beobachten")
    console.print("  [yellow]confirm[/yellow]  – Alarm, manuell bestätigen")
    console.print("  [red]auto[/red]     – sofort blockieren")
    cfg.firewall_mode = Prompt.ask("Modus", choices=["monitor","confirm","auto"], default=cfg.firewall_mode)

    console.print()
    console.print(Rule("[bold magenta]Threat Intelligence[/bold magenta]"))
    cfg.threat_intel_enabled   = Confirm.ask("Threat-Intel-Feeds aktivieren?", default=cfg.threat_intel_enabled)
    if cfg.threat_intel_enabled:
        cfg.threat_intel_auto_block = Confirm.ask("Bekannte IPs automatisch blockieren?",
                                                   default=cfg.threat_intel_auto_block)

    console.print()
    console.print(Rule("[bold cyan]E-Mail[/bold cyan]"))
    cfg.email_enabled = Confirm.ask("E-Mail-Benachrichtigungen?", default=cfg.email_enabled)
    if cfg.email_enabled:
        cfg.email_smtp      = Prompt.ask("SMTP-Server", default=cfg.email_smtp)
        cfg.email_port      = IntPrompt.ask("SMTP-Port", default=cfg.email_port)
        cfg.email_user      = Prompt.ask("Benutzername", default=cfg.email_user)
        cfg.email_password  = Prompt.ask("Passwort", password=True)
        cfg.email_recipient = Prompt.ask("Empfänger", default=cfg.email_recipient or cfg.email_user)
        cfg.email_sender    = cfg.email_user
        ok, msg = EmailNotifier.test_connection(cfg)
        console.print(msg)

    if PLYER_OK:
        cfg.notify_desktop = Confirm.ask("Desktop-Benachrichtigungen?", default=cfg.notify_desktop)

    cfg.export_csv = Confirm.ask("CSV-Report schreiben?", default=cfg.export_csv)

    console.print()
    console.print(Rule("[bold magenta]Syslog / SIEM[/bold magenta]"))
    cfg.syslog_enabled = Confirm.ask("Syslog-Export aktivieren?", default=cfg.syslog_enabled)
    if cfg.syslog_enabled:
        cfg.syslog_host     = Prompt.ask("SIEM Hostname/IP", default=cfg.syslog_host)
        cfg.syslog_port     = IntPrompt.ask("Syslog-Port", default=cfg.syslog_port)
        cfg.syslog_protocol = Prompt.ask("Protokoll", choices=["udp","tcp"], default=cfg.syslog_protocol)
        cfg.syslog_tag      = Prompt.ask("Tag", default=cfg.syslog_tag)
        ok, msg = SyslogExporter.test_connection(cfg)
        console.print(msg)

    cfg.save()
    console.print("[green]✅  Konfiguration gespeichert.[/green]")
    return cfg


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    auto_mode   = "--auto"  in sys.argv
    force_setup = "--setup" in sys.argv

    console.print()
    from rich.panel import Panel
    console.print(Panel.fit(
        "[bold white]NET-FIRE-MONITOR  v3.9  –  Terminal-Modus[/bold white]\n"
        "[dim]Firewall · Threat Intelligence · E-Mail · Syslog/SIEM[/dim]",
        border_style="blue", title="[bold blue]Willkommen[/bold blue]",
    ))

    # Root-Check
    if platform.system() in ("Linux","Darwin") and os.geteuid() != 0:
        console.print("[bold red]❌  Root-Rechte erforderlich. Bitte mit sudo starten![/bold red]")
        sys.exit(1)

    cfg = Config.load()

    if force_setup or (not auto_mode and (
        not CONFIG_FILE.exists() or Confirm.ask("Einstellungen anpassen?", default=False)
    )):
        cfg = setup_wizard(cfg)

    # ── Engines initialisieren ─────────────────────────────────────────────
    console.print("\n[cyan]⚙️   Initialisiere Engines …[/cyan]")
    _core._firewall    = FirewallEngine()
    _core._email       = EmailNotifier(cfg) if cfg.email_enabled else None
    _core._rule_engine = RuleEngine(cfg)

    mode_col = {"monitor":"green","confirm":"yellow","auto":"red"}.get(cfg.firewall_mode,"white")
    console.print(f"  🔥 Firewall-Modus: [{mode_col}]{cfg.firewall_mode.upper()}[/{mode_col}]")
    console.print(f"  🌐 Interface:      [cyan]{cfg.interface or 'alle'}[/cyan]")
    console.print(f"  🔍 BPF-Filter:     [dim]{cfg.bpf_filter[:60]}[/dim]")

    if cfg.threat_intel_enabled:
        console.print("  ☠️   Threat Intelligence: [cyan]wird geladen …[/cyan]")
        _core._threat_intel = ThreatIntelManager(cfg)
        time.sleep(1)
        console.print(f"  ☠️   Cache: [cyan]{_core._threat_intel.get_count():,} Einträge[/cyan]")

    if cfg.email_enabled:
        console.print(f"  📧  E-Mail: [cyan]{cfg.email_recipient}[/cyan]")

    if cfg.syslog_enabled:
        _core._syslog = SyslogExporter(cfg)
        console.print(f"  📡  Syslog: [cyan]{cfg.syslog_protocol.upper()} → {cfg.syslog_host}:{cfg.syslog_port}[/cyan]")

    console.print(f"  📋  Regeln: [cyan]{len(_core._rule_engine.rules)} aktive Regel(n)[/cyan]")

    # ── Neustart-Wiederherstellung ─────────────────────────────────────────
    console.print("\n[cyan]🔄  Stelle letzten Zustand wieder her …[/cyan]")
    stats = restore_on_startup(_core._firewall)
    if stats["restored_blocks"] > 0:
        console.print(f"  🔒 [yellow]{stats['restored_blocks']} blockierte IP(s) wiederhergestellt[/yellow]")
    if stats["restored_rules"] > 0:
        console.print(f"  📋 [yellow]{stats['restored_rules']} Firewall-Regel(n) wiederhergestellt[/yellow]")
    if stats["whitelist"] > 0 or stats["blacklist"] > 0:
        console.print(f"  🛡️  Whitelist ({stats['whitelist']}) / Blacklist ({stats['blacklist']}) wiederhergestellt")
    if all(v == 0 for v in stats.values()):
        console.print("  ✅ Kein vorheriger Zustand vorhanden – Neustart.")

    # Letzten State anzeigen
    last = load_state()
    if last:
        saved_at = last.get("saved_at","")[:19].replace("T"," ")
        console.print(f"\n[dim]📂  Letzter Snapshot: {saved_at} | Alarme: {last.get('alert_count',0)} | "
                      f"Geblockte IPs: {len(last.get('blocked_ips',[]))}[/dim]")

    # ── Baseline ──────────────────────────────────────────────────────────
    mon = NetworkMonitor(cfg)
    console.print(f"\n[cyan]🔍  Überprüfe Baseline …[/cyan]")

    with Progress(TextColumn("[cyan]{task.description}"), BarColumn(),
                  TextColumn("[cyan]{task.completed}/{task.total} s"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Baseline", total=cfg.average_period)
        done = threading.Event()
        def _prog():
            for _ in range(cfg.average_period):
                if done.is_set(): break
                time.sleep(1); progress.advance(task, 1)
        t = threading.Thread(target=_prog, daemon=True); t.start()
        from_snapshot = mon.measure_baseline(use_saved=True)
        done.set(); t.join()

    if from_snapshot:
        console.print(f"[green]✅  Baseline aus Snapshot: {mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}[/green]")
        console.print("[dim]   (Gespeicherte Baseline – kein Warten nötig)[/dim]")
    else:
        console.print(f"[green]✅  Baseline gemessen: {mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}[/green]")
    console.print("\n[dim]Live-Dashboard startet … [Strg+C] zum Beenden[/dim]")
    time.sleep(1)

    # ── Live-Dashboard ─────────────────────────────────────────────────────
    with Live(build_layout(mon, cfg), console=console, refresh_per_second=2, screen=True) as live:
        t = threading.Thread(target=mon.run_monitor_loop, daemon=True); t.start()
        try:
            while t.is_alive():
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
