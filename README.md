# 🛡️ SQLi-AttackLab: Advanced SQL Injection Exploitation & Defense Suite

[![Database](https://img.shields.io/badge/Database-MySQL%208.0-00758F.svg?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-000000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Standard](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20(A03%3A2021)-E0234E.svg?style=for-the-badge)](https://owasp.org/Top10/A03_2021-Injection/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

An interactive, enterprise-grade penetration testing and application security laboratory engineered to demonstrate real-world **SQL Injection (SQLi) attack mechanics**, AST query manipulation, database enumeration, and defense-in-depth mitigations against **MySQL 8.0**.

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [Architecture & System Design](#-architecture--system-design)
- [Security Modules](#-security-modules)
  - [Module 1: Authentication Bypass & Query Logic Manipulation](#module-1-authentication-bypass--query-logic-manipulation)
  - [Module 2: Union-Based Injection & Schema Enumeration](#module-2-union-based-injection--schema-enumeration)
  - [Module 3: Error-Based & Blind/Time-Based Inference](#module-3-error-based--blindtime-based-inference)
  - [Module 4: Advanced Filter Evasion & Static Code Analysis (SAST)](#module-4-advanced-filter-evasion--static-code-analysis-sast)
- [Installation & Quickstart](#-installation--quickstart)
- [Database Schema Architecture](#-database-schema-architecture)
- [Mitigation Analysis: Prepared Statements](#-mitigation-analysis-prepared-statements)
- [Security & Ethics Disclaimer](#-security--ethics-disclaimer)

---

## 🎯 Executive Overview

Despite decades of awareness, **SQL Injection (CWE-89)** remains one of the most destructive web application security vulnerabilities. Poorly sanitized inputs in data access layers allow adversaries to subvert application logic, read unauthorized business records, escalate privileges, and compromise database engines.

**SQLi-AttackLab** provides security researchers, penetration testers, and software engineers with a realistic, sandboxed environment to examine query exploitation behaviors side-by-side with industry-standard remediation techniques.

```
                              ┌────────────────────────────────────────┐
                              │           Attacker / Client            │
                              └───────────────────┬────────────────────┘
                                                  │ HTTP POST (Payload)
                                                  ▼
                              ┌────────────────────────────────────────┐
                              │         Flask Application Engine       │
                              ├───────────────────┬────────────────────┤
                              │ Vulnerable Mode   │ Remediated Mode    │
                              │ (Dynamic String)  │ (Prepared Stmts)   │
                              └─────────┬─────────┴──────────┬─────────┘
                    Raw Interpolated SQL│                    │ Parameterized Query + Bind Vars
                                        ▼                    ▼
                              ┌────────────────────────────────────────┐
                              │            MySQL 8.0 Server            │
                              │   - Parser & AST Engine                │
                              │   - Query Execution Plan               │
                              │   - Audit Logger (`query_audit_logs`)  │
                              └────────────────────────────────────────┘
```

---

## 🏛️ Security Modules

The platform is organized into four modular vulnerability laboratories:

### Module 1: Authentication Bypass & Query Logic Manipulation
* **Tautology Injections**: Exploits delimiter escapes (`'`) and boolean logic (`OR 1=1`) to force predicates to evaluate to `TRUE`.
* **Inline Comment Truncation**: Utilizes MySQL comment markers (`-- `, `#`, `/* ... */`) to discard subsequent password verification checks.
* **Parentheses & Bracket Balancing**: Demonstrates how nested query conditions (`WHERE (user = '...') AND (pass = '...')`) require structured quote-bracket termination (`') OR ('1'='1`).
* **Live Query Inspector**: Side-by-side AST breakdown highlighting injected keywords vs. literal strings.

### Module 2: Union-Based Injection & Schema Enumeration
* **Column Count Discovery**: Algorithmic projection testing via `ORDER BY n` and `UNION SELECT NULL` vectors.
* **Reflection Point Mapping**: Locating data-type compatible fields that reflect dynamically on the client interface.
* **Metadata & Schema Dumping**: Harvesting system catalog information directly from `information_schema.tables` and `information_schema.columns`.
* **Confidential Data Exfiltration**: Targeted extraction of administrative tokens, API keys, and sensitive business entities.

### Module 3: Error-Based & Blind/Time-Based Inference
* **XPath / Error Disclosure**: Triggering deliberate syntax faults via MySQL XML functions (`EXTRACTVALUE()`, `UPDATEXML()`) to exfiltrate query output inside error messages.
* **Boolean Blind Extraction**: Algorithmic binary-search extraction using `SUBSTRING()` and `ASCII()` comparisons.
* **Time-Based Side-Channel**: Precision latency testing via `SLEEP()` and `BENCHMARK()` with millisecond visual response profiling.

### Module 4: Advanced Filter Evasion & Static Code Analysis (SAST)
* **Second-Order Injections**: Demonstrating stored payload vectors that trigger during deferred background transactions.
* **WAF & Filter Bypass**: Circumventing naive signature filters using comment-nesting (`/**/`), alternative whitespace, and URL/hex encodings.
* **Static Query Auditor (SAST)**: Developer workbench that detects unsafe dynamic string formatting and auto-converts queries to parameterized equivalents.
* **Audit Reporting**: Generates structured vulnerability assessments formatted to OWASP compliance standards.

---

## ⚡ Installation & Quickstart

### Prerequisites
* **Python 3.10+**
* **MySQL Server 8.0+** running locally (or via Docker)

### 1. Clone the Repository
```bash
git clone https://github.com/souladitya087/SQLi-AttackLab-MySQL.git
cd SQLi-AttackLab-MySQL
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Environment Configuration
The application defaults to `root:root` on `localhost:3306`. To customize credentials, create a `.env` file:
```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=your_secure_password
DB_NAME=sqli_lab_db
SECRET_KEY=your_random_secret_key
```

### 4. Initialize Database & Seed Assets
Run the automated schema generator to provision tables, mock assets, and challenge flags:
```bash
python init_db.py
```

### 5. Launch the Security Console
```bash
python app.py
```
Open your browser at **`http://127.0.0.1:5000`** to access the dashboard.

---

## 🗄️ Database Schema Architecture

The laboratory provisions a dedicated, segregated MySQL database (`sqli_lab_db`):

| Table | Purpose | Sample Schema Columns |
| :--- | :--- | :--- |
| `users` | Primary authentication records | `id`, `username`, `password`, `role`, `email`, `api_key` |
| `products` | E-commerce catalog for UNION extraction | `id`, `name`, `category`, `price`, `stock`, `description` |
| `system_secrets` | Restricted flags and tokens for challenges | `id`, `secret_name`, `secret_value`, `classification` |
| `query_audit_logs` | Real-time security telemetry | `id`, `lab_module`, `executed_query`, `is_parameterized`, `execution_status`, `timestamp` |

---

## 🔬 Practical Exploitation Walkthroughs

### Module 1: Authentication Bypass Lab
* **Scenario 1.1: Tautology Injections (`' OR 1=1 -- `)**:
  * Injected payload breaks string literal delimiters and appends an unconditionally TRUE predicate (`OR 1=1`), forcing MySQL to return the primary administrator record.
* **Scenario 1.2: Inline Comment Truncation (`admin' -- ` or `admin' #`)**:
  * Exploits MySQL's comment syntax (`-- ` with space or `#`) to truncate the rest of the query, discarding password checks entirely.
* **Scenario 1.3: Parentheses Balancing (`') OR ('1'='1`)**:
  * Balances grouped conditions in parenthesized query structures to prevent MySQL syntax parsing faults.

### Module 2: Union-Based Injection & Schema Enumeration Lab
* **Scenario 2.1: Column Count Determination**:
  * Probe with `Hardware' ORDER BY 1 -- ` up to `Hardware' ORDER BY 5 -- ` (succeeds).
  * Incrementing to `Hardware' ORDER BY 6 -- ` triggers **MySQL Error 1054** (`Unknown column '6' in 'order clause'`), establishing that the base query projects exactly 5 columns.
* **Scenario 2.2: Data Type Reflection Mapping**:
  * Test compatibility with:
    ```sql
    ' UNION SELECT 101, 'Probe Name', 'Probe Category', 13.37, 'Probe Description' -- 
    ```
  * Identifies which fields render onto the web catalog and checks numeric vs string column casting.
* **Scenario 2.3: System & Engine Fingerprinting**:
  * Extract engine metadata using MySQL global functions:
    ```sql
    ' UNION SELECT 101, @@version, database(), 0, user() -- 
    ```
* **Scenario 2.4: Information Schema Harvesting & Exfiltration**:
  * Extract table names from MySQL's system catalog:
    ```sql
    ' UNION SELECT 101, table_name, table_schema, 0, table_type FROM information_schema.tables WHERE table_schema=database() -- 
    ```
  * Extract column definitions from target table `system_secrets`:
    ```sql
    ' UNION SELECT 101, column_name, data_type, 0, table_name FROM information_schema.columns WHERE table_name='system_secrets' -- 
    ```
  * Exfiltrate confidential credentials and harvest the challenge flag:
    ```sql
    ' UNION SELECT id, secret_name, classification, 0, secret_value FROM system_secrets -- 
    ```
  * Awards: `FLAG{mysql_information_schema_exfiltration_pwned}`.

---

## 🛡️ Mitigation Analysis: Prepared Statements

Every module features a dual-engine architecture permitting real-time comparison between vulnerable and secure implementations.

### Insecure Dynamic Concatenation (Vulnerable)
```python
# Unsafe dynamic string formatting:
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```
* **Failure Mode**: The MySQL query compiler treats user input as executable SQL syntax tokens.

### Parameterized Prepared Statements (Remediated)
```python
# Secure parameter binding:
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))
```
* **Defense Mechanism**: The statement template is parsed and compiled by the database server *prior* to receiving parameters. Input values are transmitted in a discrete data channel and treated strictly as literal literals, preventing syntax alteration regardless of payload complexity.

---

## 🧪 Automated Verification Suite

Run automated unit and integration tests to verify platform stability:
```bash
python test_app.py
```

---

## ⚠️ Security & Ethics Disclaimer

This project is created strictly for **educational, security research, and authorized application auditing purposes**. The authors assume no liability for misuse of the techniques described herein. Always obtain explicit written authorization before conducting vulnerability assessments against third-party systems.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
