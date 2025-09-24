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
- TheHarvester - other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources 
- Hunter.io - this is  an email hunting tool that will let you obtain contact information associated with the domain
- OSINT Framework - OSINT Framework provides the collection of OSINT tools based on various categories
-- An attacker would also use social media websites such as LinkedIn, Facebook, Twitter, and Instagram to collect information on a specific victim he would want to attack or the company. The information found on social media can be beneficial for an attacker to conduct a phishing attack.
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


# 🧠 Unified Kill Chain (UKC) – Modern Attack Lifecycle Framework

The **Unified Kill Chain (UKC)** expands on the traditional Lockheed Martin Cyber Kill Chain by incorporating tactics and techniques from the **MITRE ATT&CK** framework.

Created by Paul Pols, the Unified Kill Chain outlines **18 stages across 3 phases**, giving defenders a broader view of **how adversaries plan, execute, and persist** across extended cyber campaigns.

---

## 🛠️ Purpose of the Unified Kill Chain

- Integrates **technical + human-centric attacks**
- Covers **initial access** to **persistence and exfiltration**
- Helps defenders detect **linked TTPs over time**, not just isolated IOCs

---

## 🔺 The 3 Phases of the Unified Kill Chain

---

### 🔹 1. Initial Foothold (Recon → Execution)

| Stage | Description |
|-------|-------------|
| **1. Reconnaissance** | Passive info gathering about targets (e.g., OSINT, social media) |
| **2. Weaponization** | Crafting payloads or tools (e.g., custom malware, phishing kits) |
| **3. Delivery** | Sending malicious content via email, USB, browser exploits |
| **4. Social Engineering** | Psychological manipulation (e.g., phishing, pretexting) |
| **5. Exploitation** | Triggering a vulnerability to gain access |
| **6. Execution** | Running the attacker's code on the victim system |

---

### 🔸 2. Network Propagation (Persistence → Credential Access)

| Stage | Description |
|-------|-------------|
| **7. Installation** | Setting up malware or backdoors (e.g., RATs) |
| **8. Command & Control (C2)** | Establishing remote comms for attacker control |
| **9. Internal Reconnaissance** | Mapping internal systems, accounts, shares |
| **10. Credential Access** | Harvesting passwords, tokens, hashes |
| **11. Privilege Escalation** | Gaining higher-level permissions |
| **12. Lateral Movement** | Spreading through the network to new systems |

---

### 🔴 3. Action on Objectives (Collection → Impact)

| Stage | Description |
|-------|-------------|
| **13. Collection** | Gathering sensitive files or data |
| **14. Exfiltration** | Transferring stolen data outside the network |
| **15. Impact** | Destroying data, deploying ransomware, defacing systems |
| **16. Defensive Evasion** | Hiding presence, clearing logs, disabling tools |
| **17. Persistence** | Maintaining access across reboots or network resets |
| **18. Command Re-Establishment** | Reconnecting after disruption (e.g., using backup C2) |

---

## 📌 Key Takeaways

- **UKC is attacker-centric**: focused on how campaigns unfold, not just individual attacks
- **Broader than Cyber Kill Chain**: includes social engineering, post-exploitation, and long-term access
- **Tightly maps to MITRE ATT&CK**: provides a bridge between **tactics** (ATT&CK) and **kill chain logic**

---

## 🧠 What I Learned

- Detecting attackers earlier in the UKC = less damage & faster response
- It's not enough to stop malware — you must disrupt **their entire campaign**
- UKC helps defenders **think like attackers** across time, not just in isolated incidents
- Ideal for threat hunting, SOC analysts, red vs blue team simulations

---

## 🔗 Further Reading

- [Unified Kill Chain Whitepaper (Paul Pols)](https://www.unifiedkillchain.com)
- [MITRE ATT&CK Matrix](https://attack.mitre.org)
- [Lockheed Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)


