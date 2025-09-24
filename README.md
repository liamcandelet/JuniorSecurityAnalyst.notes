# JuniorSecurityAnalyst.notes
# 🧠 Pyramid of Pain (TryHackMe Lab Notes)

## What is the Pyramid of Pain?

The Pyramid of Pain is a cybersecurity concept that illustrates how difficult it is for an attacker when you detect and respond to different types of Indicators of Compromise (IOCs).

Created by David Bianco, the idea is:
> The higher up the pyramid, the more pain we inflict on attackers.

---

## 🔺 Levels of the Pyramid

1. **Hash Values**  
   Example: SHA-256 hash of malware file  
   🔹 Easy to change – minimal disruption to attacker

2. **IP Addresses**  
   Example: 185.100.87.202 (malicious IP)  
   🔹 Low effort for attacker to rotate IPs or use proxies

3. **Domain Names**  
   Example: badstuff[.]xyz  
   🔹 Attackers can register dozens of cheap domains

4. **Artifacts**  
   Example: A DLL written to a known path, registry change  
   🔸 Detecting artifacts requires behavioral monitoring

5. **Tools**  
   Example: PowerShell Empire, Cobalt Strike  
   🔥 If defenders detect tools, attackers need custom code

6. **TTPs (Tactics, Techniques, and Procedures)**  
   Example: Lateral movement via RDP + credential dumping  
   🔥🔥 Highest impact – forces attackers to rethink strategy

---

## 💡 What I Learned from TryHackMe

- Defenders must **move up the pyramid** to be more effective
- Focusing only on IOCs like IPs and hashes = **cat-and-mouse game**
- Detecting behaviors and patterns = **real threat hunting**
- This concept ties directly into frameworks like **MITRE ATT&CK**


# 🔗 Cyber Kill Chain (Lockheed Martin Model)

The **Cyber Kill Chain** is a framework developed by Lockheed Martin to describe the stages of a cyber attack.  
Understanding this model helps defenders **detect, disrupt, and respond** to threats at various stages of the attack lifecycle.

---

## 🧱 The 7 Stages of the Kill Chain

### 1. 🛰️ **Reconnaissance**
> Attacker gathers information about the target (e.g., open ports, employees, technologies used)

- Tools: Google Dorking, Shodan, LinkedIn scraping
- Defender’s Job: Detect suspicious scanning or OSINT attempts (via threat intelligence)

---

### 2. 📦 **Weaponization**
> Attacker creates a malicious payload (e.g., malware + exploit + document)

- Example: Embedding a reverse shell into a PDF
- Defender’s Job: Analyze malware samples, sandbox files

---

### 3. ✉️ **Delivery**
> Payload is delivered via phishing, USB drop, watering hole, etc.

- Common Methods: Malicious email attachments, infected websites
- Defender’s Job: Email filtering, attachment scanning, user awareness training

---

### 4. 💥 **Exploitation**
> Payload is triggered, exploiting a vulnerability in the system

- Example: Buffer overflow triggered by malicious file
- Defender’s Job: Patch management, vulnerability scanning, EDR alerts

---

### 5. 🧬 **Installation**
> Malware installs a backdoor or trojan to maintain access

- Tools: Remote Access Trojans (RATs), rootkits
- Defender’s Job: Detect new services, registry changes, suspicious files

---

### 6. 🕹️ **Command and Control (C2)**
> Attacker communicates with the compromised system remotely

- Methods: HTTP/S, DNS tunneling, ICMP
- Defender’s Job: Monitor for beaconing, detect outbound anomalies, block C2 domains/IPs

---

### 7. 🎯 **Actions on Objectives**
> Attacker completes their mission: data exfiltration, destruction, privilege escalation

- Goals: Steal data, install ransomware, move laterally
- Defender’s Job: Detect lateral movement, unusual file access, data exfiltration

---

## 🔐 Defensive Strategy

| Stage | Early Detection Wins |
|-------|----------------------|
| ✅ Recon & Weaponization | Prevent delivery and minimize exposure |
| ✅ Delivery & Exploitation | Email filtering, patching, user training |
| ✅ Installation & C2 | EDR, network monitoring, DNS analysis |
| ✅ Objectives | Incident response, privilege auditing, backups |

---

## 🧠 What I Learned

- Attacks follow a logical sequence — breaking any link **disrupts the whole chain**
- Blue teams can **detect and prevent** at multiple stages
- The Kill Chain maps well to **MITRE ATT&CK** for modern threat modeling
- Proactive defense is about **anticipating behaviors**, not just reacting to alerts

---

## 📌 Related Concepts
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- Pyramid of Pain
- TTPs (Tactics, Techniques, and Procedures)
