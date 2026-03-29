
# 🧠 30-Day Elite Cybersecurity Project Plan (PHP + Web)

## 🎯 FINAL SYSTEM (Non-negotiable)

By Day 30 you must be able to **live demonstrate**:

* Break login using SQL Injection
* See attack logged in dashboard
* Enable defense → attack fails

If you can’t *prove* all three → your project is weak.

---

# 🏗️ SYSTEM DESIGN (Lock before Day 1)

You are building **3 layers**:

```
[ User ] → [ Vulnerable App ] → [ Secure Layer (WAF) ] → [ Database ]
                                ↓
                           [ Dashboard ]
```

👉 Most people don’t separate layers. That’s why their projects look amateur.

---

# 📅 WEEK 1 — BUILD & BREAK (Days 1–7)

## 🎯 Goal: Create a system that is EASY to hack

---

## ✅ Day 1 — Environment Setup (No excuses)

**Tasks:**

* Install XAMPP
* Start Apache + MySQL
* Create DB: `cyber_lab`

**Tables:**

```sql
users(id, email, password)
comments(id, user_id, comment)
uploads(id, filename, path)
logs(id, type, payload, ip, created_at)
```

**Output:**

* DB visible in phpMyAdmin

**Mistake:**

* Overcomplicating schema → don’t

---

## ✅ Day 2 — Core Structure

**Tasks:**

* Create:

  * `index.php`
  * `login.php`
  * `config/db.php`
* Setup DB connection

**Output:**

* Page loads + DB connects

**Mistake:**

* Mixing DB logic everywhere → keep it in `/config`

---

## ✅ Day 3 — Authentication (Intentionally Weak)

**Tasks:**

* Register + Login system

**DO NOT:**

* Hash passwords
* Use prepared statements

**Output:**

* User can login normally

**Mistake:**

* Accidentally making it secure → don’t be smart here

---

## ✅ Day 4 — SQL Injection (Break it)

**Attack:**

```
' OR 1=1 --
```

**Tasks:**

* Test login bypass
* Add logging:

  * capture payload
  * store IP

**Output:**

* Login bypass works
* Entry appears in `logs`

**Mistake:**

* If it doesn’t break → your query is wrong

---

## ✅ Day 5 — XSS (Stored Attack)

**Tasks:**

* Build comment system
* Print raw input

**Attack:**

```html
<script>alert('XSS')</script>
```

**Output:**

* Alert executes when page loads

**Mistake:**

* Using `htmlspecialchars()` too early → NO

---

## ✅ Day 6 — File Upload Exploit

**Tasks:**

* Upload feature
* Allow ALL file types

**Attack:**

* Upload `.php` file:

```php
<?php system($_GET['cmd']); ?>
```

**Output:**

* Access file via browser and run commands

**Mistake:**

* If file doesn’t execute → your upload path is wrong

---

## ✅ Day 7 — CSRF (Silent Attack)

**Tasks:**

* Password change form
* No token

**Output:**

* Request works without verification

---

# 📅 WEEK 2 — REAL ATTACKER MODE (Days 8–14)

## 🎯 Goal: Stop playing beginner—learn real attack flow

---

## ✅ Day 8 — SQL Injection Deep Dive

**Tasks:**

* Extract DB info:

```
' UNION SELECT null, database() --
```

**Output:**

* DB name visible

---

## ✅ Day 9 — Data Extraction

**Tasks:**

* Dump user table

**Output:**

* See usernames/passwords

---

## ✅ Day 10 — Proxy Tools

Use:

* Burp Suite
* OWASP ZAP

**Tasks:**

* Intercept login request
* Modify payload

**Output:**

* You control request manually

**Mistake:**

* Just installing tools without using them

---

## ✅ Day 11 — Logging System Upgrade

**Tasks:**

* Add:

  * user_agent
  * attack_type
  * timestamp

**Output:**

* Detailed logs

---

## ✅ Day 12 — Detection Engine (Start WAF Brain)

**Tasks:**
Create function:

```php
detectAttack($input)
```

Detect:

* SQL keywords
* `<script>`
* `.php`

---

## ✅ Day 13 — Dashboard (Basic)

**Tasks:**

* Show logs in table

**Output:**

* Admin can see attacks

---

## ✅ Day 14 — Attack Classification

**Tasks:**

* Assign severity:

  * High (SQLi)
  * Medium (File upload)
  * Low (XSS)

---

# 📅 WEEK 3 — DEFENSE ENGINEERING (Days 15–21)

## 🎯 Goal: Convert weak system → secure system

---

## ✅ Day 15 — SQL Injection Fix

Switch to:

```php
PDO prepared statements
```

**Output:**

* Injection fails

---

## ✅ Day 16 — XSS Fix

Use:

```php
htmlspecialchars()
```

---

## ✅ Day 17 — Secure Upload

**Rules:**

* MIME check
* Rename file
* Move outside `/public`

---

## ✅ Day 18 — CSRF Protection

**Tasks:**

* Generate token
* Validate on POST

---

## ✅ Day 19 — Password Security

Use:

```php
password_hash()
password_verify()
```

---

## ✅ Day 20 — Session Security

**Tasks:**

* session_regenerate_id()
* Secure cookies

---

## ✅ Day 21 — Central Security Layer

Create:

```
/secure-layer/firewall.php
```

**This handles ALL input**

👉 This is where your project becomes serious.

---

# 📅 WEEK 4 — ADVANCED SYSTEM (Days 22–30)

## 🎯 Goal: Build something interview-level

---

## ✅ Day 22 — IP Tracking

Track:

* Requests per IP
* Failed attempts

---

## ✅ Day 23 — IP Blocking

**Rule:**

* > 5 attacks → block IP

---

## ✅ Day 24 — Rate Limiting

**Example:**

* 5 login attempts / minute

---

## ✅ Day 25 — Live Alerts

Dashboard shows:

* “SQL Injection detected”

---

## ✅ Day 26 — Mini WAF (Core)

**Flow:**

```
Request → Scan → Allow / Block → Log
```

👉 This is your BEST feature

---

## ✅ Day 27 — Attack Automation

**Tasks:**

* Script sends payloads automatically

---

## ✅ Day 28 — UI Upgrade

* Graphs
* Stats
* Clean dashboard

---

## ✅ Day 29 — Documentation

Write:

* attack → exploit → fix

---

## ✅ Day 30 — FINAL DEMO

You must show:

1. Attack succeeds
2. Dashboard logs it
3. WAF blocks it

---

# 💥 Hard Truth

* If you skip attack phase → you’re not in cybersecurity
* If you skip logging → no visibility
* If you skip WAF → no depth

Most people quit at Day 12.

---

# 🚀 What You Actually Become

Not “PHP guy”

But someone who can say:

> “I built a vulnerable system, exploited it, and engineered a defense layer.”

