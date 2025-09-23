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
