# 🔐 Web Security Labs – OWASP Top 10

This repository contains **hands-on web application security labs**
focused on real-world vulnerabilities from the **OWASP Top 10**.

The goal is to demonstrate **practical exploitation, impact analysis,
and clear remediation guidance** — not just theory.

---

## 🎯 Objectives

• Understand how common web vulnerabilities work in real applications  
• Practice manual testing techniques used by security engineers  
• Learn attacker mindset and defensive remediation  
• Build strong fundamentals for AppSec & Pentesting roles  

---

## 🧪 Labs Included

### 1️⃣ Insecure Direct Object Reference (IDOR)
**Category:** Broken Access Control  
**Description:**  
Users can access or modify other users’ data by changing object IDs.

**Impact:**  
• Account takeover  
• Data leakage  
• Privacy violations  

**Fix:**  
• Enforce server-side authorization  
• Validate object ownership  

---

### 2️⃣ Cross-Site Scripting (XSS)
**Category:** Injection  
**Description:**  
Unsanitized input allows JavaScript execution in victim browsers.

**Impact:**  
• Session hijacking  
• Credential theft  

**Fix:**  
• Input validation  
• Output encoding  
• Content Security Policy (CSP)  

---

### 3️⃣ Authentication & Authorization Flaws
**Category:** Broken Authentication  
**Description:**  
Weak auth checks allow privilege escalation.

**Impact:**  
• Unauthorized access  
• Admin takeover  

**Fix:**  
• Proper role checks  
• Secure session handling  

---

### 4️⃣ Business Logic Vulnerabilities
**Category:** Logic Flaws  
**Description:**  
Application flow can be abused without breaking technical controls.

**Impact:**  
• Financial loss  
• Abuse of features  

**Fix:**  
• Threat modeling  
• Abuse case testing  

---

## 🛠️ Tools Used

• Burp Suite  
• Manual HTTP request manipulation  
• Browser DevTools  
• Custom test cases  

---

## 📌 Notes

• These labs are **educational**  
• Inspired by real-world security testing scenarios  
• Designed for beginners → intermediate security engineers  

---

## 🚀 Who This Is For

• Cyber Security Analysts  
• Application Security Engineers  
• Pentesters  
• Bug Bounty Hunters  
• Students learning Web Security  

---

## 📬 Author

**Priyanshu Kumar Thakur (Gravion)**  
🌐 https://gravionshieldx.com  
📧 priyanshukumarthakur937@gmail.com  

⭐ Feel free to fork, learn, and contribute!
