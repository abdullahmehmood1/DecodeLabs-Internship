# 🛡️ DecodeLabs Cybersecurity Training — Batch 2026

> **Track:** Junior Analyst | **Institution:** University of Central Punjab  
> **Program:** DecodeLabs Industrial Training Kit | **Batch:** 2026

---

## 📁 Repository Structure

```
DecodeLabs-CyberSecurity/
│
├── README.md
│
├── Week1-Project1/
│   └── password_strength_checker.py
│
├── Week2-Project2/
│   └── encryption_decryption.py
│
└── Week3-Project3/
    └── phishing_awareness_analysis.py
```

---

## 🔐 Project 1 — Password Strength Checker

**Track:** Defensive Logic | **Language:** Python  
**Slide Reference:** DecodeLabs Cyber Security Project 1 Kit

### 📌 Goal
Build a program that evaluates whether a password is **Weak**, **Medium**, or **Strong** using string handling, entropy analysis, and security policy logic.

### ✅ Key Requirements Implemented
| Requirement | Status |
|---|---|
| Check password length (< 8 = immediate fail) | ✔ |
| Check uppercase letters [A-Z] | ✔ |
| Check digits [0-9] | ✔ |
| Check symbols !@#$%... | ✔ |
| Display strength result | ✔ |

### 🧠 Key Concepts
- **The Zero Point Rule** — passwords under 8 characters fail instantly due to exponential brute-force risk
- **Pythonic `any()` pattern** — C-optimized, short-circuit evaluation instead of manual loops
- **Score-based classification** — each criterion adds +1 (max score = 4)
- **Timing-attack safety** — `hmac.compare_digest()` used for common password comparison
- **O(n) linear scan** — validation time grows linearly, not exponentially

### 📊 Strength Classification
```
Score 0-1  →  🔴 Weak
Score 2-3  →  🟡 Medium
Score 4    →  🟢 Strong
```

### ▶️ How to Run
```bash
python password_strength_checker.py
```

### 🧪 Test Results
```
[PASS]  abc               →  Weak
[PASS]  password          →  Weak  ⚠ (common)
[PASS]  longenough1       →  Medium
[PASS]  LongEnough1       →  Medium
[PASS]  Pass@1234         →  Strong
[PASS]  Tr0ub4dor&3       →  Strong
[PASS]  (empty)           →  Invalid

Results: 7/7 tests passed
```

### 💡 Bonus Features
- Common/leaked password blacklist (12 entries)
- Constant-time comparison via `hmac.compare_digest()` (prevents timing attacks)
- Masked password display in output (security best practice)
- Interactive CLI loop




---

## 🔒 Project 2 — Basic Encryption & Decryption

**Track:** Cryptographic Phase | **Language:** Python  
**Slide Reference:** DecodeLabs Cyber Security Project 2 Kit

### 📌 Goal
Implement a working encryption and decryption system using the **Caesar Cipher** and **Vigenère Cipher**, demonstrating core cryptographic concepts through mathematical logic.

### ✅ Key Requirements Implemented
| Requirement | Status |
|---|---|
| Encrypt user text using Caesar Cipher | ✔ |
| Decrypt the encrypted text | ✔ |
| Display both encrypted and decrypted output | ✔ |
| Handle edge cases (spaces, punctuation, digits) | ✔ |
| User-defined shift key | ✔ |
| Bonus: Vigenère Cipher | ✔ |

### 🧠 Key Concepts
- **ASCII Logic** — "We don't shift letters; we shift integers." (`ord()` / `chr()`)
- **Encryption formula** — `E_n(x) = (x + n) % 26`
- **Decryption formula** — `D_n(x) = (x - n) % 26`
- **Modular arithmetic** — handles Z→A wrap-around (Y(24) + 3 = 27 % 26 = 1 = B)
- **Symmetric encryption** — the same key that locks also unlocks
- **Vigenère Cipher** — polyalphabetic substitution that defeats frequency analysis

### 📐 Algorithm Visualization (Slide 11)
```
Char 'A'  →  ASCII(65)  →  -Base(65)→0  →  +Key(3)→3  →  %26→3  →  +Base→68  →  Char 'D'
```

### ▶️ How to Run
```bash
python encryption_decryption.py
```

### 🧪 Test Results
```
Caesar Tests:
[PASS]  "HELLO"         shift=3   →  "KHOOR"
[PASS]  "ATTACK AT DAWN" shift=13  →  "NGGNPX NG QNJA"  (ROT13)
[PASS]  "xyz"           shift=3   →  "abc"  (wrap-around)
[PASS]  "Hello, World!" shift=5   →  "Mjqqt, Btwqi!"
[PASS]  "ABC abc 123"   shift=1   →  "BCD bcd 123"  (digits preserved)

Vigenère Tests:
[PASS]  "HELLO"           key="KEY"    →  "RIJVS"
[PASS]  "Attack at Dawn"  key="LEMON"  →  "Lxfopv ef Rnhr"
[PASS]  "DecodeLabs 2026" key="CYBER"  →  "FcdsugJbfj 2026"

Results: 9/9 tests passed
```

### 💡 Bonus Features
- Vigenère Cipher defeats frequency analysis vulnerability of Caesar (Slide 14)
- User-selectable cipher and custom shift/keyword (Conclusion recommendation)
- Full IPO cycle demo on startup
- Interactive CLI for live encryption/decryption

---

## 🎣 Project 3 — Phishing Awareness Analysis

**Track:** Detection Phase — The Human Firewall | **Language:** Python  
**Slide Reference:** DecodeLabs Cyber Security Project 3 Kit

### 📌 Goal
Analyze sample emails and messages to identify phishing attempts by detecting all **11 Red Flags**, domain spoofing patterns, cognitive triggers, and generating a triage verdict following the decision tree.

### ✅ Key Requirements Implemented
| Requirement | Status |
|---|---|
| Identify suspicious links and keywords | ✔ |
| List red flags found in phishing messages | ✔ |
| Explain why the message is unsafe | ✔ |
| Triage decision (Safe / Suspicious / Malicious) | ✔ |
| Red Flag Quick Reference Checklist | ✔ |
| Interactive analyzer for custom emails | ✔ |

### 🚩 All 11 Red Flags Implemented (Slides 15–17)

| ID | Red Flag | Severity | Slide |
|---|---|---|---|
| RF-01 | Sender-Domain Mismatch | HIGH | 15 |
| RF-02 | Fake Forwarded Chains | MEDIUM | 15 |
| RF-03 | Browser-in-the-Browser (BitB) | HIGH | 15 |
| RF-04 | Dangerous Attachments (.iso, .scr, .hta) | CRITICAL | 15 |
| RF-05 | Urgent Bypass Requests | CRITICAL | 16 |
| RF-06 | Requests for Sensitive Information | CRITICAL | 16 |
| RF-07 | Alarmist Activity Alerts | HIGH | 16 |
| RF-08 | MFA Fatigue | HIGH | 16 |
| RF-09 | Security Callback Scams (TOAD) | HIGH | 17 |
| RF-10 | Unsolicited QR Code Prompts | HIGH | 17 |
| RF-11 | Deepfake / Impersonation Fraud | CRITICAL | 17 |

### 🎯 Domain Spoofing Detection (Slide 12–13)
- **Typosquatting** — `amaz0n.com`, `paypa1.com`
- **Combosquatting** — `yourcompany-secure-login.com`
- **Subdomain Trap** — reads URLs right-to-left to find true root
- **Suspicious TLDs** — `.tk`, `.xyz`, `.click`, `.online`
- **URL Shorteners** — `bit.ly`, `tinyurl`, `goo.gl`

### 🧠 Cognitive Triggers Detected (Slide 14)
```
URGENCY    →  "immediately", "30 minutes", "account locked"
AUTHORITY  →  "ceo", "it department", "government"
FEAR/GREED →  "legal action", "prize", "tax refund"
CURIOSITY  →  "see what your colleague said", "photo of you"
```

### 📊 Triage Decision Tree (Slide 24)
```
Severity Score ≥ 6  OR  Dangerous Attachment  →  🔴 MALICIOUS  →  Block & Escalate
Severity Score 3–5                             →  🟡 SUSPICIOUS →  Warn User
Severity Score 0–2                             →  🟢 SAFE       →  Close
```

### 📧 5 Sample Emails Analyzed
| Email | Attack Type | Verdict | Score |
|---|---|---|---|
| EMAIL-01 | BEC Whaling — CEO Wire Transfer | 🔴 MALICIOUS | 12/20 |
| EMAIL-02 | Mass Phishing — Microsoft Impersonation | 🔴 MALICIOUS | 19/20 |
| EMAIL-03 | Callback Phishing (TOAD) — Fake Subscription | 🔴 MALICIOUS | 7/20 |
| EMAIL-04 | Spear Phishing — HR Impersonation | 🔴 MALICIOUS | 16/20 |
| EMAIL-05 | Deepfake + Vishing Combo | 🔴 MALICIOUS | 20/20 |

### ▶️ How to Run
```bash
python phishing_awareness_analysis.py
```

### 💡 Interactive Mode
After the auto-analysis, the program drops into interactive mode:
```
[INPUT #1] Enter message text (or 'quit'):
> Your account has been suspended. Click here immediately to verify.
>
# Press ENTER on blank line to submit — instant triage report generated
```

### 💡 Bonus Features
- Red Flag Quick Reference Checklist for non-technical users (Conclusion recommendation)
- Regex-based URL/domain pattern scanner
- Severity scoring system (0–20)
- Multi-email counter — analyze as many messages as needed

---

## 🧰 Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | All projects |
| `re` module | Regex URL/domain scanning (Project 3) |
| `hmac` module | Timing-attack-safe comparison (Project 1) |
| `string` module | Symbol set definition (Project 1) |
| `textwrap` module | Report formatting (Project 3) |

No external libraries required — runs on standard Python 3.

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/DecodeLabs-CyberSecurity.git
cd DecodeLabs-CyberSecurity

# Run any project
python Week1-Project1/password_strength_checker.py
python Week2-Project2/encryption_decryption.py
python Week3-Project3/phishing_awareness_analysis.py
```

---

## 📚 Concepts Covered

| Concept | Project |
|---|---|
| String handling & conditional logic | P1 |
| Entropy & password policy | P1 |
| Timing attacks & `hmac` | P1 |
| ASCII math & modular arithmetic | P2 |
| Symmetric encryption | P2 |
| Frequency analysis vulnerability | P2 |
| Phishing taxonomy (Mass/Spear/Whaling) | P3 |
| Domain spoofing (Typosquatting/Combosquatting) | P3 |
| Social engineering psychology | P3 |
| Email triage & incident response | P3 |

---

## 👤 Author

**King** — BS Software Engineering, University of Central Punjab (2022–2026)  
DecodeLabs Cybersecurity Training | Batch 2026  

---

*"The modern cybersecurity perimeter is no longer the network firewall. It is the user."*  
*— DecodeLabs Project 3, Slide 5*
