# direct_send_test.py

A Python tool for testing **direct send / direct-to-MX** vulnerabilities during authorised penetration testing engagements. Determines whether a target mail server accepts unauthenticated SMTP connections that bypass Secure Email Gateway (SEG) filtering layers such as Mimecast, Proofpoint, or Defender for Office 365.

> **⚠️ Authorised use only.** This tool is intended for use by security professionals during engagements where explicit written permission has been obtained. Unauthorised use against systems you do not own or have permission to test is illegal.

---

## Background

Organisations commonly deploy SEGs as their primary email security control. If the backend mail server (Exchange, Exchange Online, Postfix, etc.) accepts SMTP connections directly from the internet without restricting source IPs to the SEG, an attacker can deliver mail — including phishing lures — that bypasses all gateway-level filtering.

Microsoft 365 tenants are particularly susceptible: the `<tenant>.mail.protection.outlook.com` EOP endpoint accepts connections from any IP by default unless an inbound connector is configured and locked to SEG source IPs.

This tool automates the process of discovering, probing, and proving this condition across all MX records for a target domain.

---

## Features

- MX record enumeration with IP resolution
- SPF and DMARC policy inspection
- SMTP banner and EHLO capability fingerprinting
- STARTTLS detection and negotiation
- AUTH mechanism enumeration (without credential use)
- M365 direct-to-EOP endpoint detection and testing
- Three operational modes: probe-only, dry-run, full send
- JSON output for pipeline integration
- Colour-coded terminal output and result summary

---

## Requirements

Python 3.10+ and one dependency:

```bash
pip install dnspython
```

---

## Installation

```bash
git clone https://github.com/Mr-Whiskerss/direct_Send
cd direct_send_test
pip install dnspython
```

---

## Usage

```
python3 direct_send_test.py -d <domain> [options]
```

### Core arguments

| Argument | Description |
|---|---|
| `-d`, `--domain` | Target domain (required) |
| `-f`, `--from-addr` | Sender address (MAIL FROM) |
| `-t`, `--to-addr` | Recipient address (RCPT TO) |
| `-H`, `--host` | Override MX lookup — test a specific host |
| `-p`, `--port` | Override port (default: test 25 and 587) |
| `--eop` | Also test the M365 direct-to-EOP endpoint |
| `--all-ports` | Test ports 25, 587, and 465 per host |
| `--timeout` | SMTP connection timeout in seconds (default: 15) |

### Mode flags

| Flag | Behaviour |
|---|---|
| `--probe-only` | DNS recon and SMTP banner/EHLO only — no MAIL FROM or RCPT TO sent |
| `--dry-run` | Full SMTP handshake through to DATA command, then RSET — no mail delivered |
| `--send --confirm` | Full delivery — both flags required to prevent accidental sends |

### Message options

| Argument | Description |
|---|---|
| `--subject` | Email subject line |
| `--body` | Inline plain-text body |
| `--body-file` | Path to HTML or text file to use as message body |
| `--html` | Treat body as HTML |

### Output

| Argument | Description |
|---|---|
| `--json <file>` | Save full results to a JSON file |

---

## Examples

### Passive recon — no mail sent

```bash
python3 direct_send_test.py -d target.com --probe-only
```

Enumerates MX records, checks SPF/DMARC policy, connects to each MX host and captures the SMTP banner and EHLO response. Nothing is sent.

---

### Dry run — prove bypass without delivery

```bash
python3 direct_send_test.py -d target.com \
  -f it-support@target.com \
  -t employee@target.com \
  --dry-run --all-ports
```

Walks the full SMTP handshake — EHLO, MAIL FROM, RCPT TO, DATA — then sends RSET before the message body. If the server returns `354 Start input` to DATA, the bypass is confirmed without delivering mail.

---

### Test M365 EOP endpoint directly

```bash
python3 direct_send_test.py -d target.com \
  -f it-support@target.com \
  -t employee@target.com \
  --eop --dry-run
```

Automatically derives the `<tenant>.mail.protection.outlook.com` endpoint and tests it alongside standard MX records.

---

### Test a known backend host on a specific port

```bash
python3 direct_send_test.py -d target.com \
  -H mail-backend.target.com -p 25 \
  --probe-only
```

---

### Full send with HTML lure body

```bash
python3 direct_send_test.py -d target.com \
  -f it-helpdesk@target.com \
  -t employee@target.com \
  --subject "Action Required: Account Re-authentication" \
  --body-file lure.html \
  --send --confirm \
  --json results.json
```

---

## Output

### Terminal

```
[ Phase 1: DNS Recon ]
[*] Checking SPF record for target.com...
[+] SPF: v=spf1 include:spf.mimecast.com -all
[*] SPF policy is -all — direct sends may be rejected if SPF is enforced at the recipient
[*] Checking DMARC record for target.com...
[!] DMARC: v=DMARC1; p=none; rua=mailto:dmarc@target.com
[-] DMARC policy=none — no enforcement, spoofed mail may pass

[ Phase 2: MX Enumeration ]
[+]  [10] eu-smtp-inbound-1.mimecast.com  (91.220.42.x)
[+]  [20] eu-smtp-inbound-2.mimecast.com  (91.220.42.x)

[ Phase 3: SMTP Probing ]

  Target: eu-smtp-inbound-1.mimecast.com
[*]   Testing port 25...
[*]   Connecting to eu-smtp-inbound-1.mimecast.com:25 (91.220.42.x)...
[+]   Banner: 220 eu-smtp-inbound-1.mimecast.com ESMTP
[+]   STARTTLS advertised
[*]   MAIL FROM: <it-support@target.com>
[+]   MAIL FROM accepted (250)
[*]   RCPT TO: <employee@target.com>
[+]   RCPT TO accepted (250) — recipient exists and server will relay
[*]   Dry-run: initiating DATA then aborting (sending RSET)
[+]   Server accepted DATA command (354) — would accept message body

════════════════════════════════════════════════════════════
  DIRECT SEND TEST SUMMARY — target.com
════════════════════════════════════════════════════════════

  SMTP Probe Results:
    eu-smtp-inbound-1.mimecast.com:25  →  REACHABLE | RCPT ACCEPTED | DATA ACCEPTED (dry-run)

[-] VULNERABLE: Mail server accepts direct connections without authentication.
```

### JSON

```json
{
  "target_domain": "target.com",
  "timestamp": "2025-03-18T09:00:00Z",
  "mx_records": [
    {
      "hostname": "eu-smtp-inbound-1.mimecast.com",
      "priority": 10,
      "resolved_ips": ["91.220.42.10"]
    }
  ],
  "smtp_results": [
    {
      "host": "eu-smtp-inbound-1.mimecast.com",
      "port": 25,
      "reachable": true,
      "accepted_rcpt": true,
      "delivery_attempted": true,
      "delivery_confirmed": false,
      "note": "Dry-run: DATA accepted, RSET sent — no mail delivered"
    }
  ]
}
```

---

## Interpreting Results

| Result | Meaning |
|---|---|
| `RCPT ACCEPTED` | Server accepted the recipient without auth — bypass condition confirmed |
| `DATA ACCEPTED (dry-run)` | Server would have accepted the full message body |
| `DELIVERED` | Mail accepted with 250 OK — full bypass proven |
| `RCPT rejected 550` | Server rejected recipient — likely enforcing relay restrictions |

**SPF/DMARC context:** Even where direct send succeeds at the SMTP layer, the receiving server may still apply SPF/DMARC checks and quarantine or reject the message. The tool reports policy posture to help assess end-to-end deliverability.

---

## Remediation Guidance

For findings write-ups, include the following recommendations:

**Microsoft 365**
- Configure an inbound connector restricted to SEG source IP ranges
- Enable Enhanced Filtering for Connectors to preserve original sender IP
- Verify MTA-STS is published and enforced

**On-premises / hybrid**
- Restrict SMTP inbound (`smtpd_client_restrictions` in Postfix, receive connectors in Exchange) to SEG IP ranges only
- Drop connections from all other sources at the perimeter firewall on port 25

**General**
- Audit all published MX records — remove any that point directly to backend infrastructure
- Monitor for SMTP connections arriving from IPs outside the SEG range

---

## Licence

MIT — see [LICENSE](LICENSE)

---

## Author

Mr-Whsikerss
