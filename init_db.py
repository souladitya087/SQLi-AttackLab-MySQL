import os
import pymysql

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "root")
DB_NAME = os.getenv("DB_NAME", "sqli_lab_db")

def init_database():
    print(f"[*] Connecting to MySQL Server at {DB_HOST}:{DB_PORT} as {DB_USER}...")
    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        autocommit=True
    )
    cursor = conn.cursor()

    print(f"[*] Creating database '{DB_NAME}' if not exists...")
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
    cursor.execute(f"USE `{DB_NAME}`;")

    print("[*] Creating table 'users'...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS `users` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `username` VARCHAR(50) NOT NULL UNIQUE,
        `password` VARCHAR(255) NOT NULL,
        `password_hash` VARCHAR(255) NOT NULL,
        `full_name` VARCHAR(100) NOT NULL,
        `email` VARCHAR(100) NOT NULL,
        `role` VARCHAR(20) NOT NULL DEFAULT 'user',
        `api_key` VARCHAR(64) NOT NULL,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    print("[*] Creating table 'products' (for Union-based modules)...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS `products` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `name` VARCHAR(100) NOT NULL,
        `category` VARCHAR(50) NOT NULL,
        `price` DECIMAL(10, 2) NOT NULL,
        `stock` INT NOT NULL DEFAULT 10,
        `description` TEXT,
        `is_confidential` BOOLEAN DEFAULT FALSE
    );
    """)

    print("[*] Creating table 'system_secrets' (for Flag & Data Exfiltration)...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS `system_secrets` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `secret_name` VARCHAR(100) NOT NULL,
        `secret_value` VARCHAR(255) NOT NULL,
        `classification` VARCHAR(20) DEFAULT 'TOP_SECRET'
    );
    """)

    print("[*] Creating table 'query_audit_logs'...")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS `query_audit_logs` (
        `id` INT AUTO_INCREMENT PRIMARY KEY,
        `lab_module` VARCHAR(50) NOT NULL,
        `executed_query` TEXT NOT NULL,
        `is_parameterized` BOOLEAN NOT NULL DEFAULT FALSE,
        `execution_status` VARCHAR(20) NOT NULL,
        `error_message` TEXT,
        `client_ip` VARCHAR(45) NOT NULL,
        `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Seed users
    print("[*] Seeding user records...")
    cursor.execute("TRUNCATE TABLE `users`;")
    users_data = [
        ('admin', 'SuperSecr3tP@ss2026!', '$2b$12$KIXH2gB85Z2m9rK.Y6Jc2uO7.k4xL0Z41uK0E7xM7rV2zU8y12345', 'Administrator', 'admin@sqli-lab.local', 'admin', 'token_mock_admin_98a76fbc43210e98d1a7b6c5'),
        ('john_doe', 'user123', '$2b$12$W9jL7m.kY6Jc2uO7.k4xL0Z41uK0E7xM7rV2zU8y12345KIXH2gB85Z2', 'John Doe', 'john@sqli-lab.local', 'user', 'token_mock_user_12b34c56d78e90f1a2b3c4d5'),
        ('alice_smith', 'alicePass2026', '$2b$12$7xM7rV2zU8y12345KIXH2gB85Z2m9rK.Y6Jc2uO7.k4xL0Z41uK0E', 'Alice Smith', 'alice@sqli-lab.local', 'analyst', 'token_mock_analyst_fe45dcba9876543210ab'),
        ('financial_auditor', 'auditor99#', '$2b$12$uO7.k4xL0Z41uK0E7xM7rV2zU8y12345KIXH2gB85Z2m9rK.Y6Jc2', 'Finance Auditor', 'audit@sqli-lab.local', 'auditor', 'token_mock_audit_a1b2c3d4e5f60718293a')
    ]
    cursor.executemany("""
    INSERT INTO `users` (`username`, `password`, `password_hash`, `full_name`, `email`, `role`, `api_key`)
    VALUES (%s, %s, %s, %s, %s, %s, %s);
    """, users_data)

    # Seed products
    print("[*] Seeding product records...")
    cursor.execute("TRUNCATE TABLE `products`;")
    products_data = [
        ('Network Tap Sensor', 'Hardware', 499.99, 15, 'Passive gigabit Ethernet monitoring appliance.', False),
        ('Encrypted Security Key v3', 'Hardware', 65.00, 120, 'FIDO2 / WebAuthn cryptographic hardware token.', False),
        ('Firewall Appliance Enterprise', 'Hardware', 1899.50, 8, 'Layer 7 deep packet inspection firewall.', False),
        ('Vulnerability Scanner Pro License', 'Software', 1200.00, 50, 'Annual enterprise vulnerability assessment subscription.', False),
        ('SIEM Log Collector Agent', 'Software', 350.00, 80, 'High-throughput event log shipping daemon.', False),
        ('Classified Prototype Drone Firmware', 'Hardware', 99999.00, 1, 'RESTRICTED: Internal defense hardware firmware build 0.9.4.', True)
    ]
    cursor.executemany("""
    INSERT INTO `products` (`name`, `category`, `price`, `stock`, `description`, `is_confidential`)
    VALUES (%s, %s, %s, %s, %s, %s);
    """, products_data)

    # Seed secrets
    print("[*] Seeding secrets and challenge flags...")
    cursor.execute("TRUNCATE TABLE `system_secrets`;")
    secrets_data = [
        ('FLAG_AUTH_BYPASS', 'FLAG{mysql_auth_tautology_bypass_mastered}', 'RESTRICTED'),
        ('FLAG_UNION_EXPLOIT', 'FLAG{mysql_information_schema_exfiltration_pwned}', 'TOP_SECRET'),
        ('FLAG_BLIND_EXPLOIT', 'FLAG{mysql_blind_and_error_inference_pwned}', 'TOP_SECRET'),
        ('ROOT_DATABASE_MASTER_TOKEN', 'tok_sec_mysql80_4981948194819481948', 'CRITICAL'),
        ('MOCK_PAYMENT_GATEWAY_KEY', 'tok_mock_payment_sample_secret_key_9481948', 'CRITICAL')
    ]
    cursor.executemany("""
    INSERT INTO `system_secrets` (`secret_name`, `secret_value`, `classification`)
    VALUES (%s, %s, %s);
    """, secrets_data)

    cursor.close()
    conn.close()
    print("[+] Database initialization complete! All tables and seed data created successfully.")

if __name__ == "__main__":
    init_database()
