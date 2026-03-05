#!/usr/bin/env python3
import hashlib
import hmac
import mimetypes
import os
import secrets
import sqlite3
import smtplib
import time
import traceback
from datetime import datetime
from email.message import EmailMessage
from html import escape
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB_PATH = os.path.join(os.path.dirname(__file__), "controle_ti.db")
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
SESSION_COOKIE = "controle_ti_session"

# In-memory session storage for MVP use.
SESSIONS = {}


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def find_logo_path() -> str | None:
    candidates = (
        "logo-nexxus.png",
        "logo-nexxus.jpg",
        "logo-nexxus.jpeg",
        "logo-nexxus.webp",
        "logo-nexxus.svg",
    )
    for filename in candidates:
        path = os.path.join(ASSETS_DIR, filename)
        if os.path.exists(path):
            return path
    # Fallback: usa a primeira imagem encontrada na pasta assets.
    if os.path.isdir(ASSETS_DIR):
        valid_ext = (".png", ".jpg", ".jpeg", ".webp", ".svg")
        for filename in sorted(os.listdir(ASSETS_DIR)):
            if filename.lower().endswith(valid_ext):
                return os.path.join(ASSETS_DIR, filename)
    return None


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return salt.hex() + ":" + key.hex()


def verify_password(password: str, stored: str) -> bool:
    salt_hex, key_hex = stored.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    key = bytes.fromhex(key_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return hmac.compare_digest(candidate, key)


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            can_view INTEGER NOT NULL DEFAULT 1,
            can_edit INTEGER NOT NULL DEFAULT 0,
            can_delete INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_tag TEXT UNIQUE NOT NULL,
            hostname TEXT NOT NULL,
            user_name TEXT,
            ip_address TEXT,
            in_ad TEXT NOT NULL DEFAULT 'Nao',
            quantity INTEGER NOT NULL DEFAULT 1,
            motherboard_model TEXT,
            motherboard_serial TEXT,
            motherboard_invoice TEXT,
            chassis_model TEXT,
            chassis_serial TEXT,
            chassis_invoice TEXT,
            memory_quantity INTEGER NOT NULL DEFAULT 1,
            memory_model TEXT,
            memory_serial TEXT,
            memory_invoice TEXT,
            hd_quantity INTEGER NOT NULL DEFAULT 1,
            hd_model TEXT,
            hd_serial TEXT,
            hd_invoice TEXT,
            hd_nvme_quantity INTEGER NOT NULL DEFAULT 1,
            hd_nvme_model TEXT,
            hd_nvme_serial TEXT,
            hd_nvme_invoice TEXT,
            psu_model TEXT,
            psu_serial TEXT,
            psu_invoice TEXT,
            cooler_model TEXT,
            cooler_serial TEXT,
            cooler_invoice TEXT,
            memory_details TEXT,
            hd_details TEXT,
            department TEXT,
            model TEXT,
            serial_number TEXT,
            brand TEXT,
            manufacturer TEXT,
            cpu_model TEXT,
            ram_spec TEXT,
            storage_spec TEXT,
            gpu_model TEXT,
            network_card TEXT,
            monitor TEXT,
            monitor_quantity INTEGER NOT NULL DEFAULT 1,
            os_name TEXT,
            os_version TEXT,
            mac_address TEXT,
            physical_location TEXT,
            status TEXT NOT NULL,
            notes TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS peripherals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            brand_model TEXT,
            serial_number TEXT,
            assigned_to TEXT,
            status TEXT NOT NULL,
            notes TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            software_name TEXT NOT NULL,
            vendor TEXT,
            license_key TEXT,
            seats_total INTEGER NOT NULL DEFAULT 1,
            seats_in_use INTEGER NOT NULL DEFAULT 0,
            expiration_date TEXT,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS change_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    ensure_machine_schema(conn)

    existing_user_cols = {
        row["name"] for row in cur.execute("PRAGMA table_info(users)").fetchall()
    }
    user_migrations = {
        "email": "TEXT",
        "can_view": "INTEGER NOT NULL DEFAULT 1",
        "can_edit": "INTEGER NOT NULL DEFAULT 0",
        "can_delete": "INTEGER NOT NULL DEFAULT 0",
    }
    for col_name, col_def in user_migrations.items():
        if col_name not in existing_user_cols:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    admin = cur.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, can_view, can_edit, can_delete, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("admin", hash_password("admin123"), "admin", 1, 1, 1, now_str()),
        )
    else:
        cur.execute(
            "UPDATE users SET can_view=1, can_edit=1, can_delete=1 WHERE username='admin'"
        )

    conn.commit()
    conn.close()


def add_log(
    username: str,
    entity_type: str,
    entity_id: int | None,
    action: str,
    details: str,
    conn: sqlite3.Connection | None = None,
):
    own_conn = conn is None
    if conn is None:
        conn = get_db()
    conn.execute(
        "INSERT INTO change_log (user_name, entity_type, entity_id, action, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, entity_type, entity_id, action, details, now_str()),
    )
    if own_conn:
        conn.commit()
        conn.close()


def parse_cookies(environ):
    cookies = {}
    raw = environ.get("HTTP_COOKIE", "")
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k] = v
    return cookies


def get_session(environ):
    cookies = parse_cookies(environ)
    token = cookies.get(SESSION_COOKIE)
    if not token:
        return None
    session = SESSIONS.get(token)
    if not session:
        return None
    if session["expires_at"] < time.time():
        del SESSIONS[token]
        return None
    return session


def get_current_user(environ):
    session = get_session(environ)
    return session["username"] if session else None


def login_user(username: str, role: str, can_view: bool, can_edit: bool, can_delete: bool):
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = {
        "username": username,
        "role": role,
        "can_view": can_view,
        "can_edit": can_edit,
        "can_delete": can_delete,
        "expires_at": time.time() + 8 * 60 * 60,
    }
    return token


def logout_user(environ):
    cookies = parse_cookies(environ)
    token = cookies.get(SESSION_COOKIE)
    if token and token in SESSIONS:
        del SESSIONS[token]


def parse_post(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length).decode("utf-8") if length else ""
    parsed = parse_qs(body)
    return {k: v[0] if v else "" for k, v in parsed.items()}


def redirect(start_response, location, headers=None):
    all_headers = [("Location", location)]
    if headers:
        all_headers.extend(headers)
    start_response("302 Found", all_headers)
    return [b""]


def render_page(
    title: str,
    content: str,
    username: str | None = None,
    alert: str = "",
    can_manage_users: bool = False,
):
    page_class = "page-" + "".join(ch.lower() if ch.isalnum() else "-" for ch in title).strip("-")
    nav = ""
    if username:
        nav = f"""
        <nav>
          <a href=\"/dashboard\" class=\"brand\" aria-label=\"Nexxus Dashboard\">
            <img src=\"/static/logo-nexxus\" alt=\"NEXXUS\" />
          </a>
          <a href=\"/machines\">Maquinas</a>
          <a href=\"/peripherals\">Perifericos</a>
          <a href=\"/licenses\">Licencas</a>
          <a href=\"/logs\">Relatorios</a>
          {"<a href='/users'>Usuarios</a>" if can_manage_users else ""}
          <span class=\"right\">Usuario: {escape(username)} | <a href=\"/logout\">Sair</a></span>
        </nav>
        """
    alert_html = f"<p class='alert'>{escape(alert)}</p>" if alert else ""
    shell_content = f"""
    <section class=\"screen-shell\">
      <div class=\"screen-topbar\"><strong>Gestão de Ativos</strong><span>| {escape(title)}</span></div>
      <div class=\"screen-body\">{alert_html}{content}</div>
    </section>
    """
    return f"""<!doctype html>
<html lang=\"pt-BR\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{escape(title)}</title>
  <style>
    :root {{ --bg:#f6f8fa; --card:#ffffff; --ink:#1f2937; --muted:#4b5563; --line:#d1d5db; --brand:#0b4b8a; --warn:#991b1b; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Verdana, Geneva, Tahoma, sans-serif; background:linear-gradient(180deg,#eef2f7 0%, var(--bg) 45%); color:var(--ink); }}
    nav {{ background:#101827; color:#fff; padding:10px 18px; display:flex; gap:18px; align-items:center; flex-wrap:wrap; }}
    nav a {{ color:#fff; text-decoration:none; font-size:14px; }}
    nav a:hover {{ text-decoration:underline; }}
    nav .right {{ margin-left:auto; font-size:13px; }}
    nav .brand {{
      display:inline-flex;
      align-items:center;
      padding:4px 10px;
      border-radius:4px;
      background:#ffffff;
      border:1px solid #e5e7eb;
      text-decoration:none;
      box-shadow:0 2px 10px rgba(0,0,0,0.22);
    }}
    nav .brand:hover {{ text-decoration:none; }}
    nav .brand img {{ height:52px; width:auto; display:block; max-width:none; object-fit:contain; }}
    .container {{ max-width:1020px; margin:28px auto; padding:0 14px; }}
    .screen-shell {{
      border:1px solid #b6c7df;
      border-radius:14px;
      overflow:hidden;
      box-shadow:0 16px 30px rgba(15, 23, 42, 0.12);
      background:linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .screen-topbar {{
      padding:14px 20px;
      color:#eaf2ff;
      background:linear-gradient(120deg, #2f8fd0 0%, #1f4d87 60%, #1a2f5f 100%);
      font-size:20px;
      display:flex;
      gap:10px;
      align-items:center;
    }}
    .screen-topbar strong {{ color:#ffffff; }}
    .screen-topbar span {{ opacity:0.92; font-weight:500; }}
    .screen-body {{ padding:16px; }}
    .card {{ background:var(--card); border:1px solid #b6c7df; border-radius:14px; padding:16px; margin-bottom:16px; box-shadow:
        0 12px 22px rgba(15, 23, 42, 0.08),
        0 2px 0 rgba(255, 255, 255, 0.9) inset,
        0 -2px 0 rgba(148, 163, 184, 0.25) inset; }}
    .page-maquinas .card {{
      border:1px solid #b6c7df;
      border-radius:14px;
      box-shadow:
        0 16px 30px rgba(15, 23, 42, 0.12),
        0 2px 0 rgba(255, 255, 255, 0.9) inset,
        0 -2px 0 rgba(148, 163, 184, 0.35) inset,
        2px 0 0 rgba(255, 255, 255, 0.65) inset,
        -2px 0 0 rgba(148, 163, 184, 0.18) inset;
      background:linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
    }}
    .machine-form {{ display:flex; flex-direction:column; gap:14px; }}
    .machine-section {{ padding-bottom:4px; border-bottom:1px solid #dbe3ed; }}
    .machine-section:last-of-type {{ border-bottom:none; }}
    .machine-sec-title {{
      display:flex;
      align-items:center;
      gap:10px;
      margin-bottom:10px;
      font-size:14px;
      color:#334155;
    }}
    .machine-sec-title strong {{
      font-size:19px;
      color:#111827;
      font-weight:700;
    }}
    .machine-grid-3 {{ display:grid; grid-template-columns:repeat(3, minmax(0, 1fr)); gap:12px; }}
    .machine-qtd-pair {{ display:grid; grid-template-columns:84px 1fr; gap:8px; }}
    .machine-status-grid {{ display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin-top:6px; }}
    .machine-status-card {{
      border:1px solid #cbd5e1;
      border-radius:10px;
      background:#f8fafc;
      padding:12px;
      display:flex;
      align-items:center;
      gap:8px;
      font-size:14px;
      color:#1f2937;
      cursor:pointer;
    }}
    .machine-status-card input[type=radio] {{ width:auto; margin:0; }}
    .machine-status-card.active {{
      border-color:#3b82f6;
      background:#dbeafe;
      box-shadow:inset 0 0 0 1px #93c5fd;
    }}
    .machine-actions {{ justify-content:flex-end; margin-top:8px; }}
    .machine-link-btn {{
      display:inline-flex;
      align-items:center;
      padding:8px 18px;
      border-radius:10px;
      border:1px solid #9ca3af;
      text-decoration:none;
      font-size:14px;
      color:#4b5563 !important;
      background:#f8fafc;
    }}
    .machine-link-btn.warn {{
      border-color:#eab308;
      color:#a16207 !important;
      background:#fffbeb;
    }}
    h1,h2 {{ margin:0 0 12px; }}
    h1 {{ font-size:28px; }}
    h2 {{ font-size:20px; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap:12px; }}
    label {{ display:block; font-size:13px; margin-bottom:6px; color:var(--muted); }}
    input, select, textarea {{ width:100%; padding:10px; border:1px solid var(--line); border-radius:8px; background:#fff; }}
    input[type=checkbox] {{ width:auto; padding:0; border:none; border-radius:0; }}
    textarea {{ min-height:80px; resize:vertical; }}
    button {{ border:0; background:var(--brand); color:#fff; padding:10px 12px; border-radius:8px; cursor:pointer; }}
    button.secondary {{ background:#374151; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th, td {{ border-bottom:1px solid var(--line); text-align:left; padding:9px 6px; vertical-align:top; }}
    th {{ color:var(--muted); font-weight:600; }}
    .actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
    .actions a {{ font-size:13px; text-decoration:none; color:var(--brand); }}
    .action-btn {{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:6px 10px;
      border:1px solid #bfdbfe;
      border-radius:8px;
      background:#dbeafe;
      color:#1e3a8a;
      text-decoration:none;
      font-size:12px;
      line-height:1;
    }}
    .action-btn:hover {{ background:#bfdbfe; text-decoration:none; }}
    .action-btn.delete {{ color:#991b1b; border-color:#fecaca; background:#fee2e2; }}
    .action-btn.delete:hover {{ background:#fecaca; }}
    .action-icon {{ font-size:13px; }}
    .alert {{ background:#fee2e2; color:var(--warn); border:1px solid #fecaca; padding:8px 10px; border-radius:8px; }}
    .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; }}
    .kpi {{ background:#0f172a; color:#fff; border-radius:10px; padding:12px; }}
    .kpi strong {{ display:block; font-size:22px; margin-top:4px; }}
    .report-sheet {{ border:1px solid #9ca3af; border-radius:8px; overflow:auto; background:#fff; }}
    .report-sheet table {{ min-width:980px; font-size:12px; }}
    .report-sheet thead th {{
      background:#1f2937;
      color:#f9fafb;
      text-transform:uppercase;
      letter-spacing:.4px;
      font-size:11px;
      border-bottom:1px solid #111827;
      position:sticky;
      top:0;
      z-index:1;
    }}
    .report-sheet tbody tr:nth-child(even) {{ background:#f9fafb; }}
    .report-sheet tbody tr.alert-row {{ background:#ffedd5; }}
    .pill {{
      display:inline-block;
      min-width:68px;
      text-align:center;
      padding:3px 8px;
      border-radius:999px;
      font-size:11px;
      font-weight:700;
    }}
    .pill.ok {{ background:#dcfce7; color:#14532d; border:1px solid #86efac; }}
    .pill.warn {{ background:#ffedd5; color:#9a3412; border:1px solid #fdba74; }}
    @media (max-width: 700px) {{
      .container {{ margin:16px auto; }}
      table {{ display:block; overflow:auto; white-space:nowrap; }}
      .machine-grid-3 {{ grid-template-columns:1fr; }}
      .machine-status-grid {{ grid-template-columns:1fr; }}
      .screen-topbar {{ font-size:18px; flex-direction:column; align-items:flex-start; }}
    }}
  </style>
</head>
<body class=\"{page_class}\">
  {nav}
  <main class=\"container\">{shell_content}</main>
</body>
</html>""".encode("utf-8")


def require_auth(environ, start_response):
    username = get_current_user(environ)
    if username:
        return username
    redirect(start_response, "/login")
    return None


def has_permission(session: dict, permission: str) -> bool:
    if session.get("role") == "admin":
        return True
    return bool(session.get(permission, False))


def ensure_machine_schema(conn: sqlite3.Connection):
    existing_machine_cols = {
        row["name"] for row in conn.execute("PRAGMA table_info(machines)").fetchall()
    }
    machine_migrations = {
        "ip_address": "TEXT",
        "in_ad": "TEXT NOT NULL DEFAULT 'Nao'",
        "quantity": "INTEGER NOT NULL DEFAULT 1",
        "motherboard_model": "TEXT",
        "motherboard_serial": "TEXT",
        "motherboard_invoice": "TEXT",
        "chassis_model": "TEXT",
        "chassis_serial": "TEXT",
        "chassis_invoice": "TEXT",
        "memory_quantity": "INTEGER NOT NULL DEFAULT 1",
        "memory_model": "TEXT",
        "memory_serial": "TEXT",
        "memory_invoice": "TEXT",
        "hd_quantity": "INTEGER NOT NULL DEFAULT 1",
        "hd_model": "TEXT",
        "hd_serial": "TEXT",
        "hd_invoice": "TEXT",
        "hd_nvme_quantity": "INTEGER NOT NULL DEFAULT 1",
        "hd_nvme_model": "TEXT",
        "hd_nvme_serial": "TEXT",
        "hd_nvme_invoice": "TEXT",
        "psu_model": "TEXT",
        "psu_serial": "TEXT",
        "psu_invoice": "TEXT",
        "cooler_model": "TEXT",
        "cooler_serial": "TEXT",
        "cooler_invoice": "TEXT",
        "memory_details": "TEXT",
        "hd_details": "TEXT",
        "brand": "TEXT",
        "manufacturer": "TEXT",
        "cpu_model": "TEXT",
        "ram_spec": "TEXT",
        "storage_spec": "TEXT",
        "gpu_model": "TEXT",
        "network_card": "TEXT",
        "monitor": "TEXT",
        "monitor_quantity": "INTEGER NOT NULL DEFAULT 1",
        "os_name": "TEXT",
        "os_version": "TEXT",
        "mac_address": "TEXT",
        "physical_location": "TEXT",
    }
    for col_name, col_def in machine_migrations.items():
        if col_name not in existing_machine_cols:
            conn.execute(f"ALTER TABLE machines ADD COLUMN {col_name} {col_def}")


def ensure_user_schema(conn: sqlite3.Connection):
    existing_user_cols = {
        row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    user_migrations = {
        "email": "TEXT",
        "can_view": "INTEGER NOT NULL DEFAULT 1",
        "can_edit": "INTEGER NOT NULL DEFAULT 0",
        "can_delete": "INTEGER NOT NULL DEFAULT 0",
    }
    for col_name, col_def in user_migrations.items():
        if col_name not in existing_user_cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_base_url(environ) -> str:
    env_url = os.environ.get("APP_BASE_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    host = environ.get("HTTP_HOST", "localhost:8080")
    scheme = environ.get("wsgi.url_scheme", "http")
    return f"{scheme}://{host}"


def send_password_reset_email(to_email: str, username: str, reset_link: str) -> tuple[bool, str]:
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_pass = os.environ.get("SMTP_PASS", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", smtp_user).strip()
    smtp_tls = os.environ.get("SMTP_USE_TLS", "1").strip() != "0"

    if not smtp_host or not smtp_from:
        return False, "SMTP nao configurado"

    msg = EmailMessage()
    msg["Subject"] = "Nexxus TI - Recuperacao de senha"
    msg["From"] = smtp_from
    msg["To"] = to_email
    msg.set_content(
        "Olá,\n\n"
        f"Foi solicitada a redefinicao de senha para o usuario {username}.\n"
        f"Use o link abaixo (validade: 30 minutos):\n{reset_link}\n\n"
        "Se voce nao solicitou, ignore este e-mail."
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            if smtp_tls:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as exc:
        return False, str(exc)
    return True, ""


def fetch_counts():
    conn = get_db()
    counts = {
        "machines": conn.execute("SELECT COUNT(*) as c FROM machines").fetchone()["c"],
        "peripherals": conn.execute("SELECT COUNT(*) as c FROM peripherals").fetchone()["c"],
        "licenses": conn.execute("SELECT COUNT(*) as c FROM licenses").fetchone()["c"],
        "logs": conn.execute("SELECT COUNT(*) as c FROM change_log").fetchone()["c"],
    }
    conn.close()
    return counts


def machine_storage_label(row: sqlite3.Row) -> str:
    storage_spec = (row["storage_spec"] or "").strip()
    if storage_spec:
        return storage_spec
    hd_mech = (row["hd_model"] or "").strip()
    hd_nvme = (row["hd_nvme_model"] or "").strip()
    parts = []
    if hd_mech:
        parts.append(f"HD Mecanico: {row['hd_quantity'] or 1}x {hd_mech}")
    if hd_nvme:
        parts.append(f"HD NVME: {row['hd_nvme_quantity'] or 1}x {hd_nvme}")
    return " | ".join(parts) if parts else "-"


def machine_report_status(row: sqlite3.Row) -> str:
    required = [
        (row["cpu_model"] or row["motherboard_model"] or "").strip(),
        (row["ram_spec"] or row["memory_model"] or "").strip(),
        (row["network_card"] or row["psu_model"] or "").strip(),
    ]
    storage_ok = bool((row["storage_spec"] or "").strip() or (row["hd_model"] or "").strip() or (row["hd_nvme_model"] or "").strip())
    return "OK" if all(required) and storage_ok else "REVISAR"


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    query = parse_qs(environ.get("QUERY_STRING", ""))
    alert = query.get("msg", [""])[0]

    if path == "/":
        user = get_current_user(environ)
        return redirect(start_response, "/dashboard" if user else "/login")

    if path == "/static/logo-nexxus":
        logo_path = find_logo_path()
        if not logo_path:
            fallback_svg = (
                "<svg xmlns='http://www.w3.org/2000/svg' width='300' height='56'>"
                "<rect width='100%' height='100%' fill='white'/>"
                "<text x='12' y='38' font-family='Verdana' font-size='30' font-weight='700' fill='#2a1b5f'>NEXXUS</text>"
                "</svg>"
            ).encode("utf-8")
            start_response("200 OK", [("Content-Type", "image/svg+xml; charset=utf-8"), ("Cache-Control", "no-cache")])
            return [fallback_svg]
        mime = mimetypes.guess_type(logo_path)[0] or "application/octet-stream"
        with open(logo_path, "rb") as f:
            payload = f.read()
        start_response("200 OK", [("Content-Type", mime), ("Cache-Control", "public, max-age=86400")])
        return [payload]

    if path == "/login":
        if method == "GET":
            form = """
            <div class=\"card\" style=\"max-width:420px;margin:40px auto;\">
              <h1>Nexxus TI - Acesso</h1>
              <form method=\"post\" action=\"/login\">
                <label>Usuario</label><input name=\"username\" required />
                <label>Senha</label><input name=\"password\" type=\"password\" required />
                <div style=\"margin-top:12px;\"><button type=\"submit\">Entrar</button></div>
              </form>
              <p style=\"margin-top:10px;\"><a href=\"/forgot-password\">Esqueci minha senha</a></p>
            </div>
            """
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [render_page("Login", form, alert=alert)]

        data = parse_post(environ)
        username = data.get("username", "").strip()
        password = data.get("password", "")
        conn = get_db()
        row = conn.execute(
            "SELECT username, password_hash, role, can_view, can_edit, can_delete FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()
        if not row or not verify_password(password, row["password_hash"]):
            return redirect(start_response, "/login?msg=Usuario+ou+senha+invalidos")

        token = login_user(
            row["username"],
            row["role"],
            bool(row["can_view"]),
            bool(row["can_edit"]),
            bool(row["can_delete"]),
        )
        headers = [("Set-Cookie", f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax")]
        return redirect(start_response, "/dashboard", headers=headers)

    if path == "/forgot-password":
        if method == "GET":
            form = """
            <div class=\"card\" style=\"max-width:460px;margin:40px auto;\">
              <h1>Recuperar Senha</h1>
              <form method=\"post\" action=\"/forgot-password\">
                <label>Usuario ou e-mail</label>
                <input name=\"identity\" required />
                <div style=\"margin-top:12px;\"><button type=\"submit\">Enviar link</button></div>
              </form>
              <p style=\"margin-top:10px;\"><a href=\"/login\">Voltar para login</a></p>
            </div>
            """
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [render_page("Recuperar Senha", form, alert=alert)]

        data = parse_post(environ)
        identity = data.get("identity", "").strip()
        conn = get_db()
        ensure_user_schema(conn)
        user_row = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ? OR email = ? LIMIT 1",
            (identity, identity),
        ).fetchone()
        if user_row and user_row["email"]:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hash_reset_token(raw_token)
            expires_at = int(time.time()) + 30 * 60
            conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_row["id"],))
            conn.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (user_row["id"], token_hash, expires_at, now_str()),
            )
            conn.commit()
            reset_link = f"{get_base_url(environ)}/reset-password?token={raw_token}"
            send_password_reset_email(user_row["email"], user_row["username"], reset_link)
        conn.close()
        return redirect(
            start_response,
            "/login?msg=Se+os+dados+existirem,+um+link+de+recuperacao+foi+enviado+por+e-mail",
        )

    if path == "/reset-password":
        token = query.get("token", [""])[0].strip()
        if method == "GET":
            if not token:
                return redirect(start_response, "/login?msg=Token+invalido")
            conn = get_db()
            ensure_user_schema(conn)
            row = conn.execute(
                """
                SELECT prt.id, prt.expires_at, prt.used_at, u.username
                FROM password_reset_tokens prt
                JOIN users u ON u.id = prt.user_id
                WHERE prt.token_hash = ?
                """,
                (hash_reset_token(token),),
            ).fetchone()
            conn.close()
            if not row or row["used_at"] or row["expires_at"] < int(time.time()):
                return redirect(start_response, "/login?msg=Token+invalido+ou+expirado")
            form = f"""
            <div class=\"card\" style=\"max-width:460px;margin:40px auto;\">
              <h1>Nova Senha</h1>
              <p>Usuario: {escape(row['username'])}</p>
              <form method=\"post\" action=\"/reset-password\">
                <input type=\"hidden\" name=\"token\" value=\"{escape(token)}\" />
                <label>Nova senha</label><input name=\"password\" type=\"password\" required minlength=\"6\" />
                <div style=\"margin-top:12px;\"><button type=\"submit\">Redefinir senha</button></div>
              </form>
            </div>
            """
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [render_page("Redefinir Senha", form, alert=alert)]

        data = parse_post(environ)
        token = data.get("token", "").strip()
        new_password = data.get("password", "")
        if not token or len(new_password) < 6:
            return redirect(start_response, "/login?msg=Dados+invalidos+para+redefinicao")
        conn = get_db()
        ensure_user_schema(conn)
        row = conn.execute(
            """
            SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at
            FROM password_reset_tokens prt
            WHERE prt.token_hash = ?
            """,
            (hash_reset_token(token),),
        ).fetchone()
        if not row or row["used_at"] or row["expires_at"] < int(time.time()):
            conn.close()
            return redirect(start_response, "/login?msg=Token+invalido+ou+expirado")
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), row["user_id"]),
        )
        conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
            (now_str(), row["id"]),
        )
        conn.commit()
        conn.close()
        return redirect(start_response, "/login?msg=Senha+redefinida+com+sucesso")

    if path == "/logout":
        logout_user(environ)
        headers = [("Set-Cookie", f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0")]
        return redirect(start_response, "/login?msg=Sessao+encerrada", headers=headers)

    username = require_auth(environ, start_response)
    if not username:
        return [b""]
    session = get_session(environ)
    if not session:
        return redirect(start_response, "/login?msg=Sessao+invalida")
    conn_user = get_db()
    ensure_user_schema(conn_user)
    user_row = conn_user.execute(
        "SELECT username, role, can_view, can_edit, can_delete FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn_user.close()
    if not user_row:
        return redirect(start_response, "/login?msg=Usuario+nao+encontrado")
    session["role"] = user_row["role"]
    session["can_view"] = bool(user_row["can_view"])
    session["can_edit"] = bool(user_row["can_edit"])
    session["can_delete"] = bool(user_row["can_delete"])
    can_manage_users = session.get("role") == "admin"

    if path == "/dashboard":
        counts = fetch_counts()
        body = f"""
        <div class=\"card\">
          <h1>Controle de Ativos TI - Nexxus</h1>
          <p>Consulte e altere hardware, perifericos e licencas com trilha de auditoria.</p>
          <div class=\"kpis\">
            <div class=\"kpi\">Maquinas<strong>{counts['machines']}</strong></div>
            <div class=\"kpi\">Perifericos<strong>{counts['peripherals']}</strong></div>
            <div class=\"kpi\">Licencas<strong>{counts['licenses']}</strong></div>
            <div class=\"kpi\">Registros de alteracao<strong>{counts['logs']}</strong></div>
          </div>
        </div>
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Dashboard", body, username, alert, can_manage_users)]

    if path == "/users":
        if not can_manage_users:
            return redirect(start_response, "/dashboard?msg=Sem+permissao+para+gerenciar+usuarios")
        conn = get_db()
        ensure_user_schema(conn)
        if method == "POST":
            try:
                data = parse_post(environ)
                user_id = data.get("id", "").strip()
                target_username = data.get("username", "").strip()
                target_email = data.get("email", "").strip()
                password = data.get("password", "")
                role = "admin" if data.get("is_admin", "") == "on" else "user"
                can_view = 1 if data.get("can_view", "") == "on" else 0
                can_edit = 1 if data.get("can_edit", "") == "on" else 0
                can_delete = 1 if data.get("can_delete", "") == "on" else 0
                if role == "admin":
                    can_view, can_edit, can_delete = 1, 1, 1
                if not target_username:
                    conn.close()
                    return redirect(start_response, "/users?msg=Usuario+e+obrigatorio")
                if user_id and not user_id.isdigit():
                    conn.close()
                    return redirect(start_response, "/users?msg=ID+de+usuario+invalido")
                if user_id:
                    conflict = conn.execute(
                        "SELECT id FROM users WHERE lower(username) = lower(?) AND id <> ?",
                        (target_username, user_id),
                    ).fetchone()
                else:
                    conflict = conn.execute(
                        "SELECT id FROM users WHERE lower(username) = lower(?)",
                        (target_username,),
                    ).fetchone()
                if conflict:
                    conn.close()
                    return redirect(start_response, "/users?msg=Nome+de+usuario+ja+existe.+Use+Editar+para+alterar")
                if user_id:
                    current = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                    if current and str(current["id"]) == user_id and role != "admin":
                        conn.close()
                        return redirect(start_response, "/users?msg=Voce+nao+pode+remover+seu+perfil+admin")
                    if password:
                        conn.execute(
                            """
                            UPDATE users SET username=?, email=?, password_hash=?, role=?, can_view=?, can_edit=?, can_delete=?
                            WHERE id=?
                            """,
                            (target_username, target_email, hash_password(password), role, can_view, can_edit, can_delete, user_id),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE users SET username=?, email=?, role=?, can_view=?, can_edit=?, can_delete=?
                            WHERE id=?
                            """,
                            (target_username, target_email, role, can_view, can_edit, can_delete, user_id),
                        )
                    add_log(username, "user", int(user_id), "update", f"Usuario {target_username} atualizado", conn=conn)
                else:
                    if not password:
                        conn.close()
                        return redirect(start_response, "/users?msg=Senha+obrigatoria+para+novo+usuario")
                    cur = conn.execute(
                        """
                        INSERT INTO users (username, email, password_hash, role, can_view, can_edit, can_delete, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (target_username, target_email, hash_password(password), role, can_view, can_edit, can_delete, now_str()),
                    )
                    add_log(username, "user", cur.lastrowid, "create", f"Usuario {target_username} cadastrado", conn=conn)
                conn.commit()
                conn.close()
                return redirect(start_response, "/users?msg=Usuario+salvo")
            except sqlite3.IntegrityError:
                conn.close()
                return redirect(start_response, "/users?msg=Nome+de+usuario+ja+existe")
            except sqlite3.OperationalError:
                conn.close()
                return redirect(start_response, "/users?msg=Erro+de+banco.+Atualize+e+tente+novamente")
            except Exception:
                traceback.print_exc()
                try:
                    conn.close()
                except Exception:
                    pass
                return redirect(start_response, "/users?msg=Erro+inesperado+ao+alterar+usuario")

        delete_id = query.get("delete", [""])[0]
        if delete_id.isdigit():
            row = conn.execute("SELECT id, username, role FROM users WHERE id=?", (delete_id,)).fetchone()
            if row:
                if row["username"] == username:
                    conn.close()
                    return redirect(start_response, "/users?msg=Voce+nao+pode+excluir+seu+proprio+usuario")
                if row["role"] == "admin":
                    admin_count = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='admin'").fetchone()["c"]
                    if admin_count <= 1:
                        conn.close()
                        return redirect(start_response, "/users?msg=Nao+e+possivel+excluir+o+ultimo+admin")
                conn.execute("DELETE FROM users WHERE id=?", (delete_id,))
                add_log(username, "user", int(delete_id), "delete", f"Usuario {row['username']} removido", conn=conn)
                conn.commit()
                conn.close()
                return redirect(start_response, "/users?msg=Usuario+excluido")

        edit_id = query.get("edit", [""])[0]
        edit_data = conn.execute("SELECT * FROM users WHERE id=?", (edit_id,)).fetchone() if edit_id.isdigit() else None
        users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        conn.close()

        user_form = {
            "id": edit_data["id"] if edit_data else "",
            "username": edit_data["username"] if edit_data else "",
            "email": edit_data["email"] if edit_data and "email" in edit_data.keys() else "",
            "is_admin": edit_data["role"] == "admin" if edit_data else False,
            "can_view": bool(edit_data["can_view"]) if edit_data else True,
            "can_edit": bool(edit_data["can_edit"]) if edit_data else False,
            "can_delete": bool(edit_data["can_delete"]) if edit_data else False,
        }

        rows_html = "".join(
            f"""
            <tr>
              <td>{u['id']}</td><td>{escape(u['username'])}</td><td>{escape(u['role'])}</td>
              <td>{escape(u['email'] or '')}</td>
              <td>{'Sim' if u['can_view'] else 'Nao'}</td><td>{'Sim' if u['can_edit'] else 'Nao'}</td><td>{'Sim' if u['can_delete'] else 'Nao'}</td>
              <td class=\"actions\">
                <a class=\"action-btn\" href=\"/users?edit={u['id']}\"><span class=\"action-icon\">&#9998;</span>Editar</a>
                <a class=\"action-btn delete\" href=\"/users?delete={u['id']}\" onclick=\"return confirm('Excluir usuario?')\"><span class=\"action-icon\">&#128465;</span>Excluir</a>
              </td>
            </tr>
            """
            for u in users
        ) or "<tr><td colspan='8'>Nenhum usuario cadastrado.</td></tr>"

        body = f"""
        <div class=\"card\">
          <h2>{'Editar Usuario' if edit_data else 'Novo Usuario'}</h2>
          <form method=\"post\" action=\"/users\">
            <input type=\"hidden\" name=\"id\" value=\"{user_form['id']}\" />
            <div class=\"grid\">
              <div><label>Usuario*</label><input name=\"username\" value=\"{escape(user_form['username'])}\" required /></div>
              <div><label>E-mail</label><input type=\"email\" name=\"email\" value=\"{escape(user_form['email'])}\" /></div>
              <div><label>Senha {'(deixe em branco para manter)' if edit_data else '*'}</label><input type=\"password\" name=\"password\" {'required' if not edit_data else ''} /></div>
            </div>
            <div class=\"grid\" style=\"margin-top:10px;\">
              <div><label><input type=\"checkbox\" name=\"is_admin\" {'checked' if user_form['is_admin'] else ''} /> Administrador</label></div>
              <div><label><input type=\"checkbox\" name=\"can_view\" {'checked' if user_form['can_view'] else ''} /> Permissao de consulta</label></div>
              <div><label><input type=\"checkbox\" name=\"can_edit\" {'checked' if user_form['can_edit'] else ''} /> Permissao de alteracao</label></div>
              <div><label><input type=\"checkbox\" name=\"can_delete\" {'checked' if user_form['can_delete'] else ''} /> Permissao de deletar</label></div>
            </div>
            <div style=\"margin-top:12px\" class=\"actions\"><button type=\"submit\">Salvar Usuario</button><a href=\"/users\" style=\"padding-top:10px\">Limpar</a></div>
          </form>
        </div>
        <div class=\"card\">
          <h2>Usuarios cadastrados</h2>
          <table>
            <thead><tr><th>ID</th><th>Usuario</th><th>Perfil</th><th>E-mail</th><th>Consulta</th><th>Alteracao</th><th>Deletar</th><th>Acoes</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Usuarios", body, username, alert, can_manage_users)]

    if path == "/machines":
        if not has_permission(session, "can_view"):
            return redirect(start_response, "/dashboard?msg=Sem+permissao+de+consulta")
        conn = get_db()
        ensure_machine_schema(conn)
        delete_id = query.get("delete", [""])[0]
        if delete_id.isdigit():
            if not has_permission(session, "can_delete"):
                conn.close()
                return redirect(start_response, "/machines?msg=Sem+permissao+de+deletar")
            conn.execute("DELETE FROM machines WHERE id=?", (delete_id,))
            add_log(username, "machine", int(delete_id), "delete", f"Maquina ID {delete_id} excluida", conn=conn)
            conn.commit()
            conn.close()
            return redirect(start_response, "/machines?msg=Registro+excluido")
        if method == "POST":
            if not has_permission(session, "can_edit"):
                conn.close()
                return redirect(start_response, "/machines?msg=Sem+permissao+de+alteracao")
            data = parse_post(environ)
            machine_id = data.get("id", "").strip()
            ram_quantity_raw = data.get("ram_quantity", "1").strip() or "1"
            try:
                ram_quantity = int(ram_quantity_raw)
            except ValueError:
                ram_quantity = 1
            if ram_quantity < 1:
                ram_quantity = 1
            storage_quantity_raw = data.get("storage_quantity", "1").strip() or "1"
            try:
                storage_quantity = int(storage_quantity_raw)
            except ValueError:
                storage_quantity = 1
            if storage_quantity < 1:
                storage_quantity = 1
            monitor_quantity_raw = data.get("monitor_quantity", "1").strip() or "1"
            try:
                monitor_quantity = int(monitor_quantity_raw)
            except ValueError:
                monitor_quantity = 1
            if monitor_quantity < 0:
                monitor_quantity = 0
            status = data.get("status", "Ativo").strip() or "Ativo"
            if status not in ("Ativo", "Em Manutencao", "Queimado", "Baixado / Descartado"):
                status = "Ativo"
            values = (
                data.get("asset_tag", "").strip(),
                data.get("hostname", "").strip(),
                data.get("user_name", "").strip(),
                data.get("ip_address", "").strip(),
                "Nao",
                1,
                data.get("brand", "").strip(),
                "",
                "",
                "",
                "",
                "",
                ram_quantity,
                data.get("ram_spec", "").strip(),
                "",
                "",
                storage_quantity,
                data.get("storage_spec", "").strip(),
                "",
                "",
                1,
                "",
                "",
                "",
                data.get("network_card", "").strip(),
                "",
                "",
                data.get("gpu_model", "").strip(),
                "",
                "",
                data.get("department", "").strip(),
                data.get("model", "").strip(),
                data.get("serial_number", "").strip(),
                data.get("brand", "").strip(),
                data.get("manufacturer", "").strip(),
                data.get("cpu_model", "").strip(),
                data.get("ram_spec", "").strip(),
                data.get("storage_spec", "").strip(),
                data.get("gpu_model", "").strip(),
                data.get("network_card", "").strip(),
                data.get("monitor", "").strip(),
                monitor_quantity,
                data.get("os_name", "").strip(),
                data.get("os_version", "").strip(),
                data.get("mac_address", "").strip(),
                data.get("physical_location", "").strip(),
                status,
                data.get("notes", "").strip(),
                now_str(),
            )
            if not values[0] or not values[1]:
                conn.close()
                return redirect(start_response, "/machines?msg=Patrimonio+e+nome+da+maquina+sao+obrigatorios")
            try:
                if machine_id:
                    conn.execute(
                        """
                        UPDATE machines SET
                        asset_tag=?, hostname=?, user_name=?, ip_address=?, in_ad=?, quantity=?,
                        motherboard_model=?, motherboard_serial=?, motherboard_invoice=?,
                        chassis_model=?, chassis_serial=?, chassis_invoice=?,
                        memory_quantity=?, memory_model=?, memory_serial=?, memory_invoice=?,
                        hd_quantity=?, hd_model=?, hd_serial=?, hd_invoice=?,
                        hd_nvme_quantity=?, hd_nvme_model=?, hd_nvme_serial=?, hd_nvme_invoice=?,
                        psu_model=?, psu_serial=?, psu_invoice=?,
                        cooler_model=?, cooler_serial=?, cooler_invoice=?,
                        department=?, model=?, serial_number=?,
                        brand=?, manufacturer=?, cpu_model=?, ram_spec=?, storage_spec=?, gpu_model=?, network_card=?,
                        monitor=?, monitor_quantity=?, os_name=?, os_version=?, mac_address=?, physical_location=?,
                        status=?, notes=?, updated_at=?
                        WHERE id=?
                        """,
                        values + (machine_id,),
                    )
                    add_log(username, "machine", int(machine_id), "update", f"Maquina {values[0]} atualizada", conn=conn)
                else:
                    cur = conn.execute(
                        """
                        INSERT INTO machines (
                          asset_tag, hostname, user_name, ip_address, in_ad, quantity,
                          motherboard_model, motherboard_serial, motherboard_invoice,
                          chassis_model, chassis_serial, chassis_invoice,
                          memory_quantity, memory_model, memory_serial, memory_invoice,
                          hd_quantity, hd_model, hd_serial, hd_invoice,
                          hd_nvme_quantity, hd_nvme_model, hd_nvme_serial, hd_nvme_invoice,
                          psu_model, psu_serial, psu_invoice,
                          cooler_model, cooler_serial, cooler_invoice,
                          department, model, serial_number,
                          brand, manufacturer, cpu_model, ram_spec, storage_spec, gpu_model, network_card,
                          monitor, monitor_quantity, os_name, os_version, mac_address, physical_location,
                          status, notes, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        values,
                    )
                    add_log(username, "machine", cur.lastrowid, "create", f"Maquina {values[0]} cadastrada", conn=conn)
                conn.commit()
                conn.close()
                return redirect(start_response, "/machines?msg=Registro+salvo")
            except sqlite3.IntegrityError:
                conn.close()
                return redirect(start_response, "/machines?msg=Tag+de+patrimonio+ja+existe")
            except sqlite3.OperationalError as exc:
                conn.close()
                if "locked" in str(exc).lower():
                    return redirect(start_response, "/machines?msg=Banco+ocupado.+Tente+novamente")
                return redirect(start_response, "/machines?msg=Erro+ao+salvar+maquina")

        edit_id = query.get("edit", [""])[0]
        edit_data = None
        if edit_id.isdigit():
            edit_data = conn.execute("SELECT * FROM machines WHERE id=?", (edit_id,)).fetchone()

        rows = conn.execute("SELECT * FROM machines ORDER BY updated_at DESC, id DESC").fetchall()
        conn.close()

        form_data = {
            "id": edit_data["id"] if edit_data else "",
            "asset_tag": (edit_data["asset_tag"] or "") if edit_data else "",
            "hostname": (edit_data["hostname"] or "") if edit_data else "",
            "serial_number": (edit_data["serial_number"] or "") if edit_data else "",
            "brand": (edit_data["brand"] or edit_data["motherboard_model"] or "") if edit_data else "",
            "model": (edit_data["model"] or "") if edit_data else "",
            "manufacturer": (edit_data["manufacturer"] or "") if edit_data else "",
            "cpu_model": (edit_data["cpu_model"] or "") if edit_data else "",
            "ram_quantity": (
                edit_data["memory_quantity"] if (edit_data and edit_data["memory_quantity"] is not None) else 1
            ),
            "ram_spec": (edit_data["ram_spec"] or edit_data["memory_model"] or "") if edit_data else "",
            "storage_quantity": (
                edit_data["hd_quantity"] if (edit_data and edit_data["hd_quantity"] is not None) else 1
            ),
            "storage_spec": (edit_data["storage_spec"] or edit_data["hd_model"] or "") if edit_data else "",
            "gpu_model": (edit_data["gpu_model"] or edit_data["cooler_model"] or "") if edit_data else "",
            "network_card": (edit_data["network_card"] or edit_data["psu_model"] or "") if edit_data else "",
            "monitor": (edit_data["monitor"] or "") if edit_data else "",
            "monitor_quantity": (
                edit_data["monitor_quantity"] if (edit_data and edit_data["monitor_quantity"] is not None) else 1
            ),
            "os_name": (edit_data["os_name"] or "") if edit_data else "",
            "os_version": (edit_data["os_version"] or "") if edit_data else "",
            "user_name": (edit_data["user_name"] or "") if edit_data else "",
            "department": (edit_data["department"] or "") if edit_data else "",
            "physical_location": (edit_data["physical_location"] or "") if edit_data else "",
            "ip_address": (edit_data["ip_address"] or "") if edit_data else "",
            "mac_address": (edit_data["mac_address"] or "") if edit_data else "",
            "status": (edit_data["status"] or "Ativo") if edit_data else "Ativo",
            "notes": (edit_data["notes"] or "") if edit_data else "",
        }

        rows_html = "".join(
            f"""
            <tr>
              <td>{r['id']}</td>
              <td>{escape(r['asset_tag'])}</td>
              <td>{escape(r['serial_number'] or '')}</td>
              <td>{escape(r['hostname'])}</td>
              <td>{escape(r['user_name'] or '')}</td>
              <td>{escape(r['department'] or '')}</td>
              <td>{escape(str(r['monitor_quantity'] or 0))}x {escape(r['monitor'] or '')}</td>
              <td>{escape(r['status'])}</td>
              <td>{escape(r['updated_at'])}</td>
              <td class=\"actions\">
                {"<a class='action-btn' href='/machines?edit=" + str(r['id']) + "'><span class='action-icon'>&#9998;</span>Editar</a>" if has_permission(session, "can_edit") else ""}
                {"<a class='action-btn delete' href='/machines?delete=" + str(r['id']) + "' onclick=\\\"return confirm('Excluir registro?')\\\"><span class='action-icon'>&#128465;</span>Excluir</a>" if has_permission(session, "can_delete") else ""}
              </td>
            </tr>
            """
            for r in rows
        ) or "<tr><td colspan='10'>Nenhuma maquina cadastrada.</td></tr>"

        form_block = f"""
        <div class=\"card\">
          <form method=\"post\" action=\"/machines\" class=\"machine-form\">
            <input type=\"hidden\" name=\"id\" value=\"{form_data['id']}\" />
            <section class=\"machine-section\">
              <div class=\"machine-sec-title\"><span>🧾</span><strong>Informações Gerais</strong></div>
              <div class=\"machine-grid-3\">
                <div><label>Número de Patrimônio*</label><input name=\"asset_tag\" value=\"{escape(form_data['asset_tag'])}\" required /></div>
                <div><label>Número de Série</label><input name=\"serial_number\" value=\"{escape(form_data['serial_number'])}\" /></div>
                <div><label>Nome da Máquina*</label><input name=\"hostname\" value=\"{escape(form_data['hostname'])}\" required /></div>
                <div><label>Marca</label><input name=\"brand\" value=\"{escape(form_data['brand'])}\" /></div>
                <div><label>Modelo</label><input name=\"model\" value=\"{escape(form_data['model'])}\" /></div>
                <div><label>Fabricante</label><input name=\"manufacturer\" value=\"{escape(form_data['manufacturer'])}\" /></div>
              </div>
            </section>

            <section class=\"machine-section\">
              <div class=\"machine-sec-title\"><span>🖥️</span><strong>Especificações de Hardware</strong></div>
              <div class=\"machine-grid-3\">
                <div><label>Processador (CPU)</label><input name=\"cpu_model\" value=\"{escape(form_data['cpu_model'])}\" /></div>
                <div class=\"machine-qtd-pair\">
                  <div><label>Qtd</label><input type=\"number\" min=\"1\" name=\"ram_quantity\" value=\"{escape(str(form_data['ram_quantity']))}\" /></div>
                  <div><label>Modelo da Memória RAM</label><input name=\"ram_spec\" value=\"{escape(form_data['ram_spec'])}\" /></div>
                </div>
                <div class=\"machine-qtd-pair\">
                  <div><label>Qtd</label><input type=\"number\" min=\"1\" name=\"storage_quantity\" value=\"{escape(str(form_data['storage_quantity']))}\" /></div>
                  <div><label>Modelo do HD/SSD</label><input name=\"storage_spec\" value=\"{escape(form_data['storage_spec'])}\" /></div>
                </div>
                <div><label>Placa de Vídeo</label><input name=\"gpu_model\" value=\"{escape(form_data['gpu_model'])}\" /></div>
                <div class=\"machine-qtd-pair\">
                  <div><label>Qtd</label><input type=\"number\" min=\"0\" name=\"monitor_quantity\" value=\"{escape(str(form_data['monitor_quantity']))}\" /></div>
                  <div><label>Modelo Monitor</label><input name=\"monitor\" value=\"{escape(form_data['monitor'])}\" /></div>
                </div>
              </div>
            </section>

            <section class=\"machine-section\">
              <div class=\"machine-sec-title\"><span>🌐</span><strong>Configurações de Rede & Sistema</strong></div>
              <div class=\"machine-grid-3\">
                <div><label>Sistema Operacional</label><input name=\"os_name\" value=\"{escape(form_data['os_name'])}\" /></div>
                <div><label>Versão do Sistema</label><input name=\"os_version\" value=\"{escape(form_data['os_version'])}\" /></div>
                <div><label>Endereço IP</label><input name=\"ip_address\" value=\"{escape(form_data['ip_address'])}\" /></div>
                <div><label>MAC Address</label><input name=\"mac_address\" value=\"{escape(form_data['mac_address'])}\" /></div>
              </div>
            </section>

            <section class=\"machine-section\">
              <div class=\"machine-sec-title\"><span>📍</span><strong>Localização & Atribuição</strong></div>
              <div class=\"machine-grid-3\">
                <div>
                  <label>Localização Física</label>
                  <select name=\"physical_location\">
                    <option value=\"Nexxus RJ\" {'selected' if form_data['physical_location'] == 'Nexxus RJ' else ''}>Nexxus RJ</option>
                    <option value=\"Nexxus SP\" {'selected' if form_data['physical_location'] == 'Nexxus SP' else ''}>Nexxus SP</option>
                  </select>
                </div>
                <div><label>Setor / Departamento</label><input name=\"department\" value=\"{escape(form_data['department'])}\" /></div>
                <div><label>Usuário Responsável</label><input name=\"user_name\" value=\"{escape(form_data['user_name'])}\" /></div>
              </div>
            </section>

            <section class=\"machine-section\">
              <div class=\"machine-sec-title\"><span>✅</span><strong>Situação Atual</strong></div>
              <div class=\"machine-status-grid\">
                <label class=\"machine-status-card {'active' if form_data['status'] == 'Ativo' else ''}\"><input type=\"radio\" name=\"status\" value=\"Ativo\" {'checked' if form_data['status'] == 'Ativo' else ''} />✅ Ativo</label>
                <label class=\"machine-status-card {'active' if form_data['status'] == 'Em Manutencao' else ''}\"><input type=\"radio\" name=\"status\" value=\"Em Manutencao\" {'checked' if form_data['status'] == 'Em Manutencao' else ''} />🔧 Manutenção</label>
                <label class=\"machine-status-card {'active' if form_data['status'] == 'Queimado' else ''}\"><input type=\"radio\" name=\"status\" value=\"Queimado\" {'checked' if form_data['status'] == 'Queimado' else ''} />🔥 Queimado</label>
                <label class=\"machine-status-card {'active' if form_data['status'] == 'Baixado / Descartado' else ''}\"><input type=\"radio\" name=\"status\" value=\"Baixado / Descartado\" {'checked' if form_data['status'] == 'Baixado / Descartado' else ''} />🗑️ Descartado</label>
              </div>
            </section>

            <label>Observações</label><textarea name=\"notes\">{escape(form_data['notes'])}</textarea>
            <div class=\"actions machine-actions\">
              <button type=\"submit\">SALVAR</button>
              <a href=\"/machines\" class=\"machine-link-btn warn\">LIMPAR</a>
              <a href=\"/dashboard\" class=\"machine-link-btn\">CANCELAR</a>
            </div>
          </form>
        </div>
        """ if has_permission(session, "can_edit") else """
        <div class=\"card\"><h2>Consulta de Maquinas</h2><p>Seu usuario possui apenas permissao de consulta.</p></div>
        """

        body = f"""
        {form_block}
        <div class=\"card\">
          <h2>Maquinas cadastradas</h2>
          <table>
            <thead><tr><th>ID</th><th>Patrimonio</th><th>Serie</th><th>Nome da maquina</th><th>Responsavel</th><th>Setor</th><th>Monitor</th><th>Status</th><th>Atualizado em</th><th>Acoes</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Maquinas", body, username, alert, can_manage_users)]

    if path == "/peripherals":
        if not has_permission(session, "can_view"):
            return redirect(start_response, "/dashboard?msg=Sem+permissao+de+consulta")
        conn = get_db()
        delete_id = query.get("delete", [""])[0]
        if delete_id.isdigit():
            if not has_permission(session, "can_delete"):
                conn.close()
                return redirect(start_response, "/peripherals?msg=Sem+permissao+de+deletar")
            conn.execute("DELETE FROM peripherals WHERE id=?", (delete_id,))
            add_log(username, "peripheral", int(delete_id), "delete", f"Periferico ID {delete_id} excluido", conn=conn)
            conn.commit()
            conn.close()
            return redirect(start_response, "/peripherals?msg=Registro+excluido")
        if method == "POST":
            if not has_permission(session, "can_edit"):
                conn.close()
                return redirect(start_response, "/peripherals?msg=Sem+permissao+de+alteracao")
            data = parse_post(environ)
            item_id = data.get("id", "").strip()
            values = (
                data.get("type", "").strip(),
                data.get("brand_model", "").strip(),
                data.get("serial_number", "").strip(),
                data.get("assigned_to", "").strip(),
                data.get("status", "Estoque").strip() or "Estoque",
                data.get("notes", "").strip(),
                now_str(),
            )
            if not values[0]:
                conn.close()
                return redirect(start_response, "/peripherals?msg=Tipo+e+obrigatorio")
            try:
                if item_id:
                    conn.execute(
                        "UPDATE peripherals SET type=?, brand_model=?, serial_number=?, assigned_to=?, status=?, notes=?, updated_at=? WHERE id=?",
                        values + (item_id,),
                    )
                    add_log(username, "peripheral", int(item_id), "update", f"Periferico {values[0]} atualizado", conn=conn)
                else:
                    cur = conn.execute(
                        "INSERT INTO peripherals (type, brand_model, serial_number, assigned_to, status, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        values,
                    )
                    add_log(username, "peripheral", cur.lastrowid, "create", f"Periferico {values[0]} cadastrado", conn=conn)
                conn.commit()
                conn.close()
                return redirect(start_response, "/peripherals?msg=Registro+salvo")
            except sqlite3.OperationalError:
                conn.close()
                return redirect(start_response, "/peripherals?msg=Banco+ocupado.+Tente+novamente")

        edit_id = query.get("edit", [""])[0]
        edit_data = conn.execute("SELECT * FROM peripherals WHERE id=?", (edit_id,)).fetchone() if edit_id.isdigit() else None
        rows = conn.execute("SELECT * FROM peripherals ORDER BY updated_at DESC, id DESC").fetchall()
        conn.close()

        data = {
            "id": edit_data["id"] if edit_data else "",
            "type": edit_data["type"] if edit_data else "",
            "brand_model": edit_data["brand_model"] if edit_data else "",
            "serial_number": edit_data["serial_number"] if edit_data else "",
            "assigned_to": edit_data["assigned_to"] if edit_data else "",
            "status": edit_data["status"] if edit_data else "Estoque",
            "notes": edit_data["notes"] if edit_data else "",
        }

        rows_html = "".join(
            f"""
            <tr>
              <td>{r['id']}</td><td>{escape(r['type'])}</td><td>{escape(r['brand_model'] or '')}</td><td>{escape(r['serial_number'] or '')}</td>
              <td>{escape(r['assigned_to'] or '')}</td><td>{escape(r['status'])}</td><td>{escape(r['updated_at'])}</td>
              <td class=\"actions\">
                {"<a class='action-btn' href='/peripherals?edit=" + str(r['id']) + "'><span class='action-icon'>&#9998;</span>Editar</a>" if has_permission(session, "can_edit") else ""}
                {"<a class='action-btn delete' href='/peripherals?delete=" + str(r['id']) + "' onclick=\\\"return confirm('Excluir registro?')\\\"><span class='action-icon'>&#128465;</span>Excluir</a>" if has_permission(session, "can_delete") else ""}
              </td>
            </tr>
            """
            for r in rows
        ) or "<tr><td colspan='8'>Nenhum periferico cadastrado.</td></tr>"

        form_block = f"""
        <div class=\"card\">
          <h2>{'Editar Periferico' if edit_data else 'Novo Periferico'}</h2>
          <form method=\"post\" action=\"/peripherals\">
            <input type=\"hidden\" name=\"id\" value=\"{data['id']}\" />
            <div class=\"grid\">
              <div><label>Tipo*</label><input name=\"type\" value=\"{escape(data['type'])}\" required /></div>
              <div><label>Marca/Modelo</label><input name=\"brand_model\" value=\"{escape(data['brand_model'])}\" /></div>
              <div><label>Serial</label><input name=\"serial_number\" value=\"{escape(data['serial_number'])}\" /></div>
              <div><label>Em uso por</label><input name=\"assigned_to\" value=\"{escape(data['assigned_to'])}\" /></div>
              <div><label>Status</label><input name=\"status\" value=\"{escape(data['status'])}\" /></div>
            </div>
            <label style=\"margin-top:10px\">Observacoes</label><textarea name=\"notes\">{escape(data['notes'])}</textarea>
            <div style=\"margin-top:12px\" class=\"actions\"><button type=\"submit\">Salvar</button><a href=\"/peripherals\" style=\"padding-top:10px\">Limpar</a></div>
          </form>
        </div>
        """ if has_permission(session, "can_edit") else """
        <div class=\"card\"><h2>Consulta de Perifericos</h2><p>Seu usuario possui apenas permissao de consulta.</p></div>
        """

        body = f"""
        {form_block}
        <div class=\"card\">
          <h2>Perifericos cadastrados</h2>
          <table>
            <thead><tr><th>ID</th><th>Tipo</th><th>Marca/Modelo</th><th>Serial</th><th>Em uso por</th><th>Status</th><th>Atualizado em</th><th>Acoes</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Perifericos", body, username, alert, can_manage_users)]

    if path == "/licenses":
        if not has_permission(session, "can_view"):
            return redirect(start_response, "/dashboard?msg=Sem+permissao+de+consulta")
        conn = get_db()
        delete_id = query.get("delete", [""])[0]
        if delete_id.isdigit():
            if not has_permission(session, "can_delete"):
                conn.close()
                return redirect(start_response, "/licenses?msg=Sem+permissao+de+deletar")
            conn.execute("DELETE FROM licenses WHERE id=?", (delete_id,))
            add_log(username, "license", int(delete_id), "delete", f"Licenca ID {delete_id} excluida", conn=conn)
            conn.commit()
            conn.close()
            return redirect(start_response, "/licenses?msg=Registro+excluido")
        if method == "POST":
            if not has_permission(session, "can_edit"):
                conn.close()
                return redirect(start_response, "/licenses?msg=Sem+permissao+de+alteracao")
            try:
                data = parse_post(environ)
                item_id = data.get("id", "").strip()
                try:
                    seats_total = int(data.get("seats_total", "1") or "1")
                except ValueError:
                    seats_total = 1
                try:
                    seats_in_use = int(data.get("seats_in_use", "0") or "0")
                except ValueError:
                    seats_in_use = 0
                if seats_total < 1:
                    seats_total = 1
                if seats_in_use < 0:
                    seats_in_use = 0
                if seats_in_use > seats_total:
                    seats_in_use = seats_total
                values = (
                    data.get("software_name", "").strip(),
                    data.get("vendor", "").strip(),
                    data.get("license_key", "").strip(),
                    seats_total,
                    seats_in_use,
                    data.get("expiration_date", "").strip(),
                    data.get("status", "Ativa").strip() or "Ativa",
                    now_str(),
                )
                if not values[0]:
                    conn.close()
                    return redirect(start_response, "/licenses?msg=Software+e+obrigatorio")
                if item_id:
                    conn.execute(
                        "UPDATE licenses SET software_name=?, vendor=?, license_key=?, seats_total=?, seats_in_use=?, expiration_date=?, status=?, updated_at=? WHERE id=?",
                        values + (item_id,),
                    )
                    add_log(username, "license", int(item_id), "update", f"Licenca {values[0]} atualizada", conn=conn)
                else:
                    cur = conn.execute(
                        "INSERT INTO licenses (software_name, vendor, license_key, seats_total, seats_in_use, expiration_date, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        values,
                    )
                    add_log(username, "license", cur.lastrowid, "create", f"Licenca {values[0]} cadastrada", conn=conn)
                conn.commit()
                conn.close()
                return redirect(start_response, "/licenses?msg=Registro+salvo")
            except sqlite3.OperationalError:
                conn.close()
                return redirect(start_response, "/licenses?msg=Banco+ocupado.+Tente+novamente")
            except Exception:
                conn.close()
                return redirect(start_response, "/licenses?msg=Erro+ao+salvar+licenca")

        edit_id = query.get("edit", [""])[0]
        edit_data = conn.execute("SELECT * FROM licenses WHERE id=?", (edit_id,)).fetchone() if edit_id.isdigit() else None
        rows = conn.execute("SELECT * FROM licenses ORDER BY updated_at DESC, id DESC").fetchall()
        conn.close()

        data = {
            "id": edit_data["id"] if edit_data else "",
            "software_name": edit_data["software_name"] if edit_data else "",
            "vendor": edit_data["vendor"] if edit_data else "",
            "license_key": edit_data["license_key"] if edit_data else "",
            "seats_total": edit_data["seats_total"] if edit_data else 1,
            "seats_in_use": edit_data["seats_in_use"] if edit_data else 0,
            "expiration_date": edit_data["expiration_date"] if edit_data else "",
            "status": edit_data["status"] if edit_data else "Ativa",
        }

        rows_html = "".join(
            f"""
            <tr>
              <td>{r['id']}</td><td>{escape(r['software_name'])}</td><td>{escape(r['vendor'] or '')}</td><td>{escape(str(r['seats_in_use']))}/{escape(str(r['seats_total']))}</td>
              <td>{escape(r['expiration_date'] or '-')}</td><td>{escape(r['status'])}</td><td>{escape(r['updated_at'])}</td>
              <td class=\"actions\">
                {"<a class='action-btn' href='/licenses?edit=" + str(r['id']) + "'><span class='action-icon'>&#9998;</span>Editar</a>" if has_permission(session, "can_edit") else ""}
                {"<a class='action-btn delete' href='/licenses?delete=" + str(r['id']) + "' onclick=\\\"return confirm('Excluir registro?')\\\"><span class='action-icon'>&#128465;</span>Excluir</a>" if has_permission(session, "can_delete") else ""}
              </td>
            </tr>
            """
            for r in rows
        ) or "<tr><td colspan='8'>Nenhuma licenca cadastrada.</td></tr>"

        form_block = f"""
        <div class=\"card\">
          <h2>{'Editar Licenca' if edit_data else 'Nova Licenca'}</h2>
          <form method=\"post\" action=\"/licenses\">
            <input type=\"hidden\" name=\"id\" value=\"{data['id']}\" />
            <div class=\"grid\">
              <div><label>Software*</label><input name=\"software_name\" value=\"{escape(data['software_name'])}\" required /></div>
              <div><label>Fabricante</label><input name=\"vendor\" value=\"{escape(data['vendor'])}\" /></div>
              <div><label>Chave Licenca</label><input name=\"license_key\" value=\"{escape(data['license_key'])}\" /></div>
              <div><label>Total de Assentos</label><input type=\"number\" min=\"1\" name=\"seats_total\" value=\"{data['seats_total']}\" /></div>
              <div><label>Assentos em Uso</label><input type=\"number\" min=\"0\" name=\"seats_in_use\" value=\"{data['seats_in_use']}\" /></div>
              <div><label>Vencimento (AAAA-MM-DD)</label><input name=\"expiration_date\" value=\"{escape(data['expiration_date'])}\" /></div>
              <div><label>Status</label><input name=\"status\" value=\"{escape(data['status'])}\" /></div>
            </div>
            <div style=\"margin-top:12px\" class=\"actions\"><button type=\"submit\">Salvar</button><a href=\"/licenses\" style=\"padding-top:10px\">Limpar</a></div>
          </form>
        </div>
        """ if has_permission(session, "can_edit") else """
        <div class=\"card\"><h2>Consulta de Licencas</h2><p>Seu usuario possui apenas permissao de consulta.</p></div>
        """

        body = f"""
        {form_block}
        <div class=\"card\">
          <h2>Licencas cadastradas</h2>
          <table>
            <thead><tr><th>ID</th><th>Software</th><th>Fabricante</th><th>Uso</th><th>Vencimento</th><th>Status</th><th>Atualizado em</th><th>Acoes</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Licencas", body, username, alert, can_manage_users)]

    if path == "/logs":
        if not has_permission(session, "can_view"):
            return redirect(start_response, "/dashboard?msg=Sem+permissao+de+consulta")
        conn = get_db()
        ensure_machine_schema(conn)
        report = query.get("report", ["all"])[0]
        if report not in ("all", "hardware_changes", "license_purchases", "total_machines"):
            report = "all"

        report_titles = {
            "all": "Relatorio geral de alteracoes",
            "hardware_changes": "Alteracoes de hardware",
            "license_purchases": "Compras de licencas",
            "total_machines": "Total de maquinas na Nexxus",
        }

        if report == "total_machines":
            total_machines = conn.execute("SELECT COUNT(*) AS c FROM machines").fetchone()["c"]
            machine_rows = conn.execute(
                """
                SELECT
                  id, user_name,
                  cpu_model, ram_spec, storage_spec, gpu_model, network_card,
                  motherboard_model, motherboard_serial, motherboard_invoice,
                  chassis_model, chassis_serial, chassis_invoice,
                  memory_quantity, memory_model,
                  hd_quantity, hd_model, hd_serial, hd_invoice,
                  hd_nvme_quantity, hd_nvme_model, hd_nvme_serial, hd_nvme_invoice,
                  psu_model
                FROM machines
                ORDER BY id DESC
                LIMIT 300
                """
            ).fetchall()
            conn.close()
            rows_html = "".join(
                f"""
                <tr class="{'alert-row' if machine_report_status(r) != 'OK' else ''}">
                  <td><span class="pill {'ok' if machine_report_status(r) == 'OK' else 'warn'}">{machine_report_status(r)}</span></td>
                  <td>{escape(r['user_name'] or '')}</td>
                  <td>{escape(r['cpu_model'] or r['motherboard_model'] or '')}</td>
                  <td>{escape(r['ram_spec'] or (str(r['memory_quantity']) + 'x ' if (r['memory_quantity'] or 0) > 0 else '') + (r['memory_model'] or ''))}</td>
                  <td>{escape(r['gpu_model'] or r['chassis_model'] or '')}</td>
                  <td>{escape(r['network_card'] or r['psu_model'] or '')}</td>
                  <td>{escape(machine_storage_label(r))}</td>
                </tr>
                """
                for r in machine_rows
            ) or "<tr><td colspan='7'>Nenhuma maquina cadastrada.</td></tr>"

            result_card = f"""
            <div class=\"card\">
              <h1>{report_titles[report]}</h1>
              <div class=\"kpis\" style=\"margin-bottom:12px;\">
                <div class=\"kpi\">Total de maquinas<strong>{total_machines}</strong></div>
              </div>
              <div class="report-sheet">
                <table>
                  <thead><tr><th>Status</th><th>Usuario</th><th>CPU</th><th>Memoria</th><th>Video</th><th>Rede</th><th>Armazenamento</th></tr></thead>
                  <tbody>{rows_html}</tbody>
                </table>
              </div>
            </div>
            """
        else:
            where_clause = ""
            if report == "hardware_changes":
                where_clause = "WHERE entity_type IN ('machine', 'peripheral') AND action = 'update'"
            elif report == "license_purchases":
                where_clause = "WHERE entity_type = 'license' AND action = 'create'"

            rows = conn.execute(
                f"SELECT * FROM change_log {where_clause} ORDER BY id DESC LIMIT 300"
            ).fetchall()
            conn.close()
            rows_html = "".join(
                f"""
                <tr class="{'alert-row' if r['action'] == 'delete' else ''}">
                  <td><span class="pill {'warn' if r['action'] == 'delete' else 'ok'}">{'DELETE' if r['action'] == 'delete' else 'OK'}</span></td>
                  <td>{r['id']}</td><td>{escape(r['created_at'])}</td><td>{escape(r['user_name'])}</td>
                  <td>{escape(r['entity_type'])}</td><td>{escape(str(r['entity_id'] or '-'))}</td><td>{escape(r['action'])}</td><td>{escape(r['details'] or '')}</td>
                </tr>
                """
                for r in rows
            ) or "<tr><td colspan='8'>Nenhum registro encontrado para esse filtro.</td></tr>"

            result_card = f"""
            <div class=\"card\">
              <h1>{report_titles[report]}</h1>
              <div class="report-sheet">
                <table>
                  <thead><tr><th>Status</th><th>ID</th><th>Data/Hora</th><th>Usuario</th><th>Entidade</th><th>ID Entidade</th><th>Acao</th><th>Detalhes</th></tr></thead>
                  <tbody>{rows_html}</tbody>
                </table>
              </div>
            </div>
            """

        body = f"""
        <div class=\"card\">
          <h2>Gerar Relatorio</h2>
          <form method=\"get\" action=\"/logs\">
            <div class=\"grid\">
              <div>
                <label>Tipo de relatorio</label>
                <select name=\"report\">
                  <option value=\"all\" {'selected' if report == 'all' else ''}>Geral (todas as alteracoes)</option>
                  <option value=\"hardware_changes\" {'selected' if report == 'hardware_changes' else ''}>Alteracoes no hardware</option>
                  <option value=\"license_purchases\" {'selected' if report == 'license_purchases' else ''}>Compras de licencas</option>
                  <option value=\"total_machines\" {'selected' if report == 'total_machines' else ''}>Total de maquinas na Nexxus</option>
                </select>
              </div>
            </div>
            <div style=\"margin-top:12px\" class=\"actions\"><button type=\"submit\">Gerar</button></div>
          </form>
        </div>
        {result_card}
        """
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [render_page("Relatorios", body, username, alert, can_manage_users)]

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return [b"Pagina nao encontrada"]


def main():
    init_db()
    host, port = "0.0.0.0", 8080
    print(f"Servidor iniciado em http://{host}:{port}")
    with make_server(host, port, app) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    main()
