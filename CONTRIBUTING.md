# Engineering Guidelines & Contribution Standards

This document outlines the software engineering principles, coding practices, and version control standards enforced across the **SQLi-AttackLab** codebase.

---

## 🏛️ Core Principles

1. **Enterprise Code Quality**: All code must be production-grade, modular, self-documenting, and maintainable.
2. **Explicit Contracts**: Functions and API handlers must use explicit Python type annotations (`typing`), robust exception handling, and descriptive variable naming.
3. **Defense-in-Depth & Pedagogical Clarity**: Both offensive mechanics (AST manipulation, syntax breakage) and defensive implementations (prepared statements, validation) must be modeled accurately against MySQL 8.0 behaviors.
4. **Zero Unhandled Exceptions**: Database operations must intercept and classify engine errors (`pymysql.MySQLError`) gracefully, recording full telemetry to `query_audit_logs`.

---

## 💻 Python & Backend Standards

* **Python Version**: `>= 3.10`
* **Style Guide**: PEP 8 compliance.
* **Typing**: Use static type annotations on all function signatures:
  ```python
  def execute_auth_attempt(
      username: str, 
      password: str, 
      scenario: str = "tautology", 
      mode: str = "vulnerable", 
      client_ip: str = "127.0.0.1"
  ) -> dict[str, Any]:
      ...
  ```
* **Database Access**: 
  * All raw connections must use context managers or structured `try...finally` blocks ensuring connection closure.
  * Parameterized queries must use database-native parameter markers (`%s` in PyMySQL) and separate tuple arguments. Never use string formatting (`f"..."`, `.format()`, `%`) for data values in remediated execution paths.
* **Docstrings**: Standardized Google or Sphinx format documenting arguments, return types, and exceptions:
  ```python
  """Executes an authentication attempt against MySQL.

  Args:
      username: The user-supplied username or SQL injection payload.
      password: The user-supplied password string.
      scenario: Target attack scenario ('tautology', 'comment_truncation', 'parenthesized').
      mode: Engine mode ('vulnerable' or 'secure').
      client_ip: Source IP for security audit logging.

  Returns:
      A dictionary containing execution status, raw query, diagnostics, and breached profile.
  """
  ```

---

## 📦 Version Control & Git Standards

All commits must strictly follow the **[Conventional Commits](https://www.conventionalcommits.org/)** specification:

```
<type>(<scope>): <short description in present tense>

[optional body providing technical rationale]
```

### Commit Types:
* `feat`: A new security module, attack vector, or platform capability.
* `fix`: Bug fix, error handling correction, or UI patch.
* `refactor`: Code reorganization that neither fixes a bug nor adds a feature.
* `security`: Enhancements to prepared statements, sanitization, or defensive controls.
* `docs`: Documentation updates, architecture diagrams, or README improvements.
* `test`: Adding or updating test suites and verification scripts.
* `chore`: Build scripts, dependencies, or configuration updates.

### Examples:
* `feat(auth): implement parenthesized query injection scenario`
* `security(db): bind parameterized values via PyMySQL prepared cursor`
* `docs(readme): add execution architecture diagram and OWASP mapping`
* `test(api): add automated regression tests for comment truncation`

---

## 🧪 Testing & Verification Protocol

Before pushing any commit to `origin/main`:
1. Run the local automated verification suite:
   ```bash
   python test_app.py
   ```
2. Verify all status codes (`200 OK`) and assertion conditions pass without regressions.
3. Verify that `query_audit_logs` in MySQL correctly records telemetry for both successful executions and syntax faults.
4. Verify working tree status:
   ```bash
   git status
   ```
