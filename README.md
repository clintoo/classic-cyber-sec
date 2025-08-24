# Classic Guide to programming and cybersec

---

## Table of Contents

* [Mindset & Ethics](#mindset--ethics)
* [Roadmap Overview](#roadmap-overview)
* [Your Starter Dev/Sec Stack](#your-starter-devsec-stack)
* [Terminal & Linux Crash Course](#terminal--linux-crash-course)
* [Networking Fundamentals](#networking-fundamentals)
* [Programming for Security: Python + Bash](#programming-for-security-python--bash)
* [Web Security 101 (OWASP Top 10)](#web-security-101-owasp-top-10)
* [Hands-on Tools & How to Use Them](#hands-on-tools--how-to-use-them)
* [Build a Home Lab (Safely!)](#build-a-home-lab-safely)
* [Blue Team Basics (Defense)](#blue-team-basics-defense)
* [Threat Modeling & IR Lite](#threat-modeling--ir-lite)
* [Cloud & Container Security Basics](#cloud--container-security-basics)
* [Crypto Primitives (the useful bits)](#crypto-primitives-the-useful-bits)
* [Practice, Projects, and Portfolio](#practice-projects-and-portfolio)
* [Certs & Learning Paths (Optional)](#certs--learning-paths-optional)
* [Checklists & Milestones](#checklists--milestones)
* [Appendix: Cheatsheets](#appendix-cheatsheets)

---

## Mindset & Ethics

* **Be curious, but lawful.** Only test systems you own or have explicit permission to test.
* **Document as you learn.** A public GitHub + notes beats memory.
* **Automate repetitive tasks.** Scripts turn you from user → builder.
* **Small daily reps win.** 45–90 minutes/day > weekend binges.

---

## Roadmap Overview

**0–3 months**

* OS basics (Linux), terminal, Git, Python, networking, HTTP.
* Use Wireshark, Nmap, `curl`, `ssh`, VS Code.
* Complete 15–25 beginner labs on platforms like TryHackMe/Hack The Box Academy (intro rooms/modules).

**4–6 months**

* Web security (OWASP Top 10), Burp Suite, ZAP, simple bug-hunting.
* Automation with Python; write small scanners/parsers.
* Start a home lab (VMs, vulnerable apps), basic logging/monitoring.

**7–12 months**

* Pick a track: **Web App**, **Blue Team/SOC**, **Cloud/IAM**, or **Red Team**.
* Build 2–3 portfolio projects, write case studies, maybe attempt an entry-level cert.

---

## Your Starter Dev/Sec Stack

**OS**: Linux (Ubuntu LTS/Debian) in a VM or dual-boot. Windows users: keep WSL2.

**Editor**: VS Code (extensions: Python, Docker, GitHub Copilot/AI of choice, Markdown).

**Shell**: Bash/Zsh + `fzf`, `ripgrep`, `bat`, `htop`, `tmux`.

**Languages**: Python 3 (primary), Bash (automation), a bit of JavaScript (web), optional Go later.

**Must-have tools**: `git`, `curl`, `wget`, `ssh`, `nmap`, `wireshark`, `tcpdump`, `openssl`, `jq`, `ufw`/`iptables`, Docker.

**Security tooling** (starter): Burp Suite Community, OWASP ZAP, Metasploit (for learning), Nikto, `sqlmap`, `ffuf`/`dirsearch`, `wordlists` (SecLists), `hashcat`, `john`, `gobuster`.

---

## Terminal & Linux Crash Course

```bash
# package management (Debian/Ubuntu)
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential git curl wget python3 python3-pip \
  nmap wireshark tcpdump jq net-tools ufw docker.io

# users & permissions
sudo adduser student && sudo usermod -aG sudo student
sudo usermod -aG wireshark $USER   # capture permissions

# networking quick look
ip addr show
ip route
ss -tulpn     # sockets

# firewall (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
```

**Wireshark display filters**

```
ip.addr == 10.0.2.15
http && ip.dst == 93.184.216.34
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

---

## Networking Fundamentals

* **Layers**: Physical → Data Link → Network (IP) → Transport (TCP/UDP) → Application (HTTP/DNS/SMTP…).
* **Key concepts**: IP addressing, subnetting, NAT, DNS, TLS, routing, common ports (80, 443, 22, 53, 3389…).
* **HTTP refresher**: methods (GET/POST/PUT/DELETE), status codes (2xx/3xx/4xx/5xx), headers (Auth, Cookies), bodies (JSON, form-data).

**Hands-on**

```bash
# DNS
nslookup example.com
# HTTP
curl -I https://example.com
# TLS cert peek
openssl s_client -connect example.com:443 -servername example.com </dev/null | openssl x509 -noout -text
# Scan a small subnet (safe in your own lab)
sudo nmap -sV -p 1-1024 192.168.56.0/24
```

---

## Programming for Security: Python + Bash

### Why Python?

* Batteries included, easy parsing (`json`, `re`, `ipaddress`), great for automation.

### Mini Projects

**1) Simple TCP Port Scanner (educational)**

```python
#!/usr/bin/env python3
import socket, sys
from concurrent.futures import ThreadPoolExecutor

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
ports = range(1, 1025)

def scan(p):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect((target, p))
        print(f"OPEN {p}")
    except:
        pass
    finally:
        s.close()

with ThreadPoolExecutor(max_workers=200) as ex:
    for p in ports:
        ex.submit(scan, p)
```

**2) HTTP Directory Fuzzer (tiny)**

```python
#!/usr/bin/env python3
import sys, requests
base = sys.argv[1]
for word in ["admin","login","uploads","backup",".git","server-status"]:
    url = f"{base.rstrip('/')}/{word}"
    try:
        r = requests.get(url, timeout=4)
        if r.status_code not in (404,):
            print(r.status_code, url)
    except requests.exceptions.RequestException:
        pass
```

**3) Bash: Log Grep + IP Count**

```bash
#!/usr/bin/env bash
# Count top talkers in access.log
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head
```

**4) Bash: Quick JSON parsing**

```bash
curl -s https://api.github.com/repos/OWASP/Top10 | jq '.stargazers_count, .open_issues_count'
```

---

## Web Security 101 (OWASP Top 10)

Understand and be able to **demonstrate + fix**:

1. **Broken Access Control** – IDORs, missing auth checks.
2. **Cryptographic Failures** – HTTP vs HTTPS, weak ciphers, no TLS.
3. **Injection** – SQL/NoSQL/OS command injection, prepared statements.
4. **Insecure Design** – missing rate limits, weak workflows.
5. **Security Misconfiguration** – default creds, open S3 buckets, verbose errors.
6. **Vulnerable & Outdated Components** – dependencies without updates/pinning.
7. **Identification & Auth Failures** – weak sessions, poor MFA.
8. **Software & Data Integrity Failures** – unsigned updates, CI/CD trust.
9. **Security Logging & Monitoring Failures** – no logs, no alerts.
10. **Server-Side Request Forgery (SSRF)** – backend fetching arbitrary URLs.

**Vulnerable → Fixed Example (Flask)**

```python
# vulnerable: SQL injection
@app.route('/user')
def user():
    uid = request.args.get('id','1')
    q = f"SELECT * FROM users WHERE id = {uid};"
    return db.execute(q).fetchone()
```

```python
# fixed: parameterized query
@app.route('/user')
def user():
    uid = int(request.args.get('id','1'))
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
```

**Burp Suite/ZAP Workflow**

1. Set browser proxy → capture traffic.
2. Crawl (spider) → map endpoints.
3. Active scan (with permission!) → confirm vulns.
4. Reproduce manually → write PoC → propose fix.

---

## Hands-on Tools & How to Use Them

### Nmap (discovery)

```bash
# host discovery
nmap -sn 192.168.56.0/24
# version + scripts on a host
sudo nmap -sV -sC -O -p- 192.168.56.101
```

### Wireshark / tcpdump (packets)

```bash
sudo tcpdump -i eth0 'tcp port 80' -w web.pcap
# later: open web.pcap in Wireshark
```

### FFUF/dirsearch (content discovery)

```bash
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404
```

### sqlmap (injection testing)

```bash
sqlmap -u 'https://t/vuln.php?id=1' --batch --risk=2 --level=2
```

### Hashcat/John (hash cracking – for **your** lab only)

```bash
# identify hash
hashid '21232f297a57a5a743894a0e4a801fc3'
# crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

> ⚠️ **Always** limit heavy scans/bruteforce to lab environments with permission.

---

## Build a Home Lab (Safely)

**Hardware**: Your main machine + 16GB RAM is fine. Optional: a used mini-PC or old laptop as a homelab box.

**Virtualization**: VirtualBox/VMware/Proxmox.

**Minimal Lab Topology**

* `attacker` (Kali/Parrot) ↔ `victim-web` (Ubuntu + vulnerable app) ↔ `victim-win` (Windows trial)
* All on a **host-only** or **NAT** network; no inbound from the internet.

**Vulnerable Targets (for practice)**

* DVWA, Juice Shop, WebGoat, VulnHub images.

**Network Segmentation**: use separate virtual networks for safety.

---

## Blue Team Basics (Defense)

**Linux Logging**

```bash
# journald
journalctl -p err -n 100
# auth
grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head
```

**Windows Quick Wins**

* Enable Audit Policies, Sysmon, and centralize logs.

**Free SIEM-ish**: Wazuh/Elastic Stack for ingesting logs from your lab.

**Detection Ideas**

* Multiple 401s → 200 from same IP.
* Outbound to rare countries/ASNs.
* New processes making unusual network calls.

---

## Threat Modeling & IR Lite

**Threat Modeling (STRIDE-lite)**

* Identify assets → diagram data flows → list threats (spoofing/tampering/etc.) → pick mitigations.

**IR Mini-Playbook**

1. **Detect** (alerts/logs)
2. **Triage** (scope, severity)
3. **Contain** (isolate host, revoke tokens)
4. **Eradicate** (remove persistence, patch)
5. **Recover** (restore, monitor)
6. **Learn** (post-incident review)

**Template**

```
Incident: <short name>
Date/Time:
Reporter:
Impact:
Evidence:
Actions Taken:
Lessons:
```

---

## Cloud & Container Security Basics

**IAM First**: least privilege, MFA, short-lived creds.

**Buckets & Secrets**

* Block public access by default, enable encryption, rotate keys.
* Store secrets in a manager (SSM/Secrets Manager/Vault) – not in code.

**Kubernetes/Docker**

```bash
# list running containers
docker ps
# minimal Dockerfile (non-root)
FROM python:3.12-slim
RUN useradd -m app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER app
CMD ["python","app.py"]
```

Security tips: read-only root FS when possible, drop capabilities, network policies, image scanning.

---

## Crypto Primitives (the useful bits)

**Hashing vs Encryption vs Signing**

* Hashing = integrity (SHA-256), one-way.
* Encryption = confidentiality (AES-GCM), reversible with key.
* Signing = authenticity (Ed25519/RSA), verify origin.

**Python demo**

```python
import hashlib, os
m = hashlib.sha256()
m.update(b"hello")
print(m.hexdigest())

# salted password hash (for learning only)
salt = os.urandom(16)
print(hashlib.pbkdf2_hmac('sha256', b'P@ssw0rd', salt, 100_000).hex())
```

**TLS in a sentence**: server proves identity with a certificate; both sides derive session keys; data is encrypted+integrity-protected.

---

## Practice, Projects, and Portfolio

**Daily reps**

* 1 packet capture, 1 small script, 1 lab note.

**Project ideas**

* Write a Python log parser (nginx/Apache) + anomaly highlights.
* Build a mini web app with **one intentional vuln**, exploit it, then fix it; publish write-up.
* Create a hardening guide for Ubuntu with automation scripts.
* Set up a Wazuh stack and write 3 detection rules.

**Write-ups**: Each project → README with: Goal, Setup, Steps, Findings, Fix, Screenshots, What I’d Improve.

---

## Certs & Learning Paths (Optional)

* **Foundations**: CompTIA A+ (IT ops), **Network+**, **Security+**.
* **Practical entry**: **eJPT** (junior penetration tester), **PNPT** (network pentest).
* **Advanced**: **OSCP** (offensive), **GSEC/GCIA/GCED** (defensive), cloud-specific (AWS SAA/Security Specialty).

Pick **one** aligned with your target role; projects > certs for most junior roles.

---

## Checklists & Milestones

**Week 0 Setup**

* [ ] Linux VM with snapshots
* [ ] VS Code + extensions
* [ ] GitHub account + first repo (notes)
* [ ] Install: nmap, wireshark, burp, zap, docker

**Month 1**

* [ ] Finish 10 beginner labs
* [ ] Write 3 scripts (scanner, parser, fetcher)
* [ ] Packet capture + analysis report

**Month 3**

* [ ] Complete OWASP Top 10 walkthroughs
* [ ] Publish 1 vulnerable app write-up (exploit + fix)
* [ ] Build home SIEM (Wazuh/Elastic) with 2 detections

**Month 6**

* [ ] Choose track; start cert OR deeper projects
* [ ] Portfolio: 3 high-quality repos + blog posts

---

## Appendix: Cheatsheets

### Git

```bash
git init && git add . && git commit -m "init"
git branch -M main && git remote add origin <url> && git push -u origin main
```

### Regex

```
# emails (good enough for logs)
[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
```

### Common Ports

```
20-21 FTP, 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP,
443 HTTPS, 3306 MySQL, 3389 RDP, 6379 Redis, 8080 Alt HTTP
```

### Linux Hardening Quick Wins

* Keep packages updated; auto-secutity-updates.
* Disable root SSH, use key-based auth.
* `ufw` default deny inbound; allow only what you need.
* Fail2ban for SSH; logrotate for logs.
* Backups with tested restore.

---

## Final Notes

* Stay legal and ethical. Get permission in writing.
* Document **everything**. Your future self (and recruiters) will thank you.
* Iterate. Security is a **practice**, not a finish line.
