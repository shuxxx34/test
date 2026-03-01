"""
SentinelHQ — Flask Backend
===========================
Handles Discord OAuth2 login, session management, and API endpoints
for the dashboard website.

pip install flask flask-session requests python-dotenv aiohttp
"""

from flask import Flask, redirect, request, session, jsonify, send_from_directory
import requests
import os
import json
import sqlite3
from datetime import datetime, timezone
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "change-this-to-a-random-string")

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_BOT_TOKEN     = os.getenv("DISCORD_TOKEN")
VPNAPI_KEY            = os.getenv("VPNAPI_KEY", "")
REDIRECT_URI          = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")

DISCORD_API    = "https://discord.com/api/v10"
DISCORD_OAUTH  = "https://discord.com/api/oauth2"
SCOPES         = "identify guilds"

DB_PATH = "sentinelhq.db"

# ─────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS member_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id TEXT NOT NULL,
                date TEXT NOT NULL,
                count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS flagged_alts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                joined_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vpn_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                provider TEXT,
                country TEXT,
                detected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id TEXT PRIMARY KEY,
                log_channel_id TEXT,
                alert_channel_id TEXT,
                auto_kick_vpn INTEGER DEFAULT 0,
                min_account_age INTEGER DEFAULT 0
            );
        """)

init_db()

# ─────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated


def get_user_guilds_with_admin():
    """Get guilds where the user has MANAGE_GUILD permission."""
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    resp = requests.get(f"{DISCORD_API}/users/@me/guilds", headers=headers)
    if resp.status_code != 200:
        return []
    guilds = resp.json()
    # Filter to guilds where user is admin or has manage_guild
    MANAGE_GUILD = 0x20
    ADMINISTRATOR = 0x8
    admin_guilds = []
    for g in guilds:
        perms = int(g.get("permissions", 0))
        if (perms & ADMINISTRATOR) or (perms & MANAGE_GUILD):
            admin_guilds.append(g)
    return admin_guilds


def is_bot_in_guild(guild_id: str) -> bool:
    """Check if our bot is in the guild."""
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    resp = requests.get(f"{DISCORD_API}/guilds/{guild_id}", headers=headers)
    return resp.status_code == 200


def get_guild_member_count(guild_id: str) -> int:
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    resp = requests.get(f"{DISCORD_API}/guilds/{guild_id}?with_counts=true", headers=headers)
    if resp.status_code == 200:
        return resp.json().get("approximate_member_count", 0)
    return 0


def check_vpn_ip(ip: str) -> dict:
    if not VPNAPI_KEY or not ip:
        return {}
    try:
        resp = requests.get(
            f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            sec = data.get("security", {})
            loc = data.get("location", {})
            net = data.get("network", {})
            return {
                "is_vpn":   sec.get("vpn", False),
                "is_proxy": sec.get("proxy", False),
                "is_tor":   sec.get("tor", False),
                "provider": net.get("autonomous_system_organization", "Unknown"),
                "country":  loc.get("country", "Unknown"),
            }
    except Exception as e:
        print(f"[VPN Check Error] {e}")
    return {}

# ─────────────────────────────────────────
# OAUTH ROUTES
# ─────────────────────────────────────────

@app.route("/login")
def login():
    """Redirect user to Discord OAuth."""
    params = {
        "client_id":     DISCORD_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         SCOPES,
    }
    from urllib.parse import urlencode
    url = f"{DISCORD_OAUTH}/authorize?{urlencode(params)}"
    return redirect(url)


@app.route("/callback")
def callback():
    """Handle Discord OAuth callback."""
    code = request.args.get("code")
    if not code:
        return redirect("/?error=no_code")

    # Exchange code for token
    data = {
        "client_id":     DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(f"{DISCORD_OAUTH}/token", data=data, headers=headers)

    if resp.status_code != 200:
        return redirect("/?error=token_exchange_failed")

    tokens = resp.json()
    access_token = tokens.get("access_token")

    # Get user info
    user_resp = requests.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    if user_resp.status_code != 200:
        return redirect("/?error=user_fetch_failed")

    user = user_resp.json()
    session["user"] = {
        "id":            user["id"],
        "username":      user["username"],
        "discriminator": user.get("discriminator", "0"),
        "avatar":        user.get("avatar"),
    }
    session["access_token"] = access_token

    # Check IP for VPN (capture their IP at login)
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if user_ip and "," in user_ip:
        user_ip = user_ip.split(",")[0].strip()

    vpn_result = check_vpn_ip(user_ip)
    if vpn_result:
        session["user"]["vpn_info"] = vpn_result
        # Note: IP is stored server-side only, never sent to the user

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ─────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────

@app.route("/api/me")
@login_required
def api_me():
    """Return current user info (no IP data)."""
    user = session["user"].copy()
    user.pop("vpn_info", None)  # Never expose IP/VPN to frontend
    return jsonify(user)


@app.route("/api/guilds")
@login_required
def api_guilds():
    """Return guilds where user has admin and bot is present."""
    guilds = get_user_guilds_with_admin()
    result = []
    for g in guilds:
        in_guild = is_bot_in_guild(g["id"])
        result.append({
            "id":       g["id"],
            "name":     g["name"],
            "icon":     g.get("icon"),
            "bot_added": in_guild,
            "members":  get_guild_member_count(g["id"]) if in_guild else 0,
        })
    return jsonify(result)


@app.route("/api/guild/<guild_id>/stats")
@login_required
def api_guild_stats(guild_id):
    """Return stats for a specific guild."""
    db = get_db()

    alts = db.execute(
        "SELECT COUNT(*) as c FROM flagged_alts WHERE guild_id=? AND status='pending'",
        (guild_id,)
    ).fetchone()["c"]

    vpns = db.execute(
        "SELECT COUNT(*) as c FROM vpn_detections WHERE guild_id=?",
        (guild_id,)
    ).fetchone()["c"]

    history = db.execute(
        "SELECT date, count FROM member_snapshots WHERE guild_id=? ORDER BY date DESC LIMIT 30",
        (guild_id,)
    ).fetchall()

    member_count = get_guild_member_count(guild_id)

    return jsonify({
        "member_count":   member_count,
        "flagged_alts":   alts,
        "vpn_detections": vpns,
        "history":        [{"date": r["date"], "count": r["count"]} for r in reversed(history)],
    })


@app.route("/api/guild/<guild_id>/alts")
@login_required
def api_guild_alts(guild_id):
    db = get_db()
    rows = db.execute(
        "SELECT * FROM flagged_alts WHERE guild_id=? ORDER BY joined_at DESC LIMIT 50",
        (guild_id,)
    ).fetchall()
    result = []
    for r in rows:
        result.append({
            "id":        r["id"],
            "user_id":   r["user_id"],
            "username":  r["username"],
            "score":     r["score"],
            "reasons":   json.loads(r["reasons"]),
            "status":    r["status"],
            "joined_at": r["joined_at"],
        })
    return jsonify(result)


@app.route("/api/guild/<guild_id>/vpn")
@login_required
def api_guild_vpn(guild_id):
    """Return VPN detections - NO IP addresses sent to client."""
    db = get_db()
    rows = db.execute(
        "SELECT id, user_id, username, detection_type, provider, country, detected_at FROM vpn_detections WHERE guild_id=? ORDER BY detected_at DESC LIMIT 50",
        (guild_id,)
    ).fetchall()
    # IP is intentionally excluded from SELECT
    return jsonify([dict(r) for r in rows])


@app.route("/api/guild/<guild_id>/alt/<int:alt_id>/action", methods=["POST"])
@login_required
def alt_action(guild_id, alt_id):
    """Ban or dismiss a flagged alt."""
    action = request.json.get("action")  # "ban" or "dismiss"
    db = get_db()

    alt = db.execute(
        "SELECT * FROM flagged_alts WHERE id=? AND guild_id=?",
        (alt_id, guild_id)
    ).fetchone()

    if not alt:
        return jsonify({"error": "Not found"}), 404

    if action == "ban":
        # Call Discord API to ban
        headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
        resp = requests.put(
            f"{DISCORD_API}/guilds/{guild_id}/bans/{alt['user_id']}",
            headers=headers,
            json={"reason": "SentinelHQ: Alt account detected"}
        )
        if resp.status_code in (200, 204):
            db.execute("UPDATE flagged_alts SET status='banned' WHERE id=?", (alt_id,))
            db.commit()
            return jsonify({"success": True, "action": "banned"})
        return jsonify({"error": "Ban failed", "discord_status": resp.status_code}), 500

    elif action == "dismiss":
        db.execute("UPDATE flagged_alts SET status='dismissed' WHERE id=?", (alt_id,))
        db.commit()
        return jsonify({"success": True, "action": "dismissed"})

    return jsonify({"error": "Invalid action"}), 400


# ─────────────────────────────────────────
# BOT WEBHOOK (bot posts data here)
# ─────────────────────────────────────────

@app.route("/webhook/member_join", methods=["POST"])
def webhook_member_join():
    """The Discord bot calls this when a member joins."""
    secret = request.headers.get("X-Sentinel-Secret")
    if secret != os.getenv("WEBHOOK_SECRET"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    guild_id  = data.get("guild_id")
    user_id   = data.get("user_id")
    username  = data.get("username")
    score     = data.get("score", 0)
    reasons   = data.get("reasons", [])
    is_vpn    = data.get("is_vpn", False)
    vpn_type  = data.get("vpn_type", "VPN")
    provider  = data.get("provider", "Unknown")
    country   = data.get("country", "Unknown")

    db = get_db()

    if score >= 60:
        db.execute(
            "INSERT INTO flagged_alts (guild_id, user_id, username, score, reasons, joined_at) VALUES (?,?,?,?,?,?)",
            (guild_id, user_id, username, score, json.dumps(reasons), datetime.now(timezone.utc).isoformat())
        )

    if is_vpn:
        db.execute(
            "INSERT INTO vpn_detections (guild_id, user_id, username, detection_type, provider, country, detected_at) VALUES (?,?,?,?,?,?,?)",
            (guild_id, user_id, username, vpn_type, provider, country, datetime.now(timezone.utc).isoformat())
        )

    db.commit()
    return jsonify({"success": True})


@app.route("/webhook/member_count", methods=["POST"])
def webhook_member_count():
    """Bot posts daily member count."""
    secret = request.headers.get("X-Sentinel-Secret")
    if secret != os.getenv("WEBHOOK_SECRET"):
        return jsonify({"error": "Unauthorized"}), 401

    data     = request.json
    guild_id = data.get("guild_id")
    count    = data.get("count")
    date     = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    db = get_db()
    db.execute(
        "INSERT INTO member_snapshots (guild_id, date, count) VALUES (?,?,?)",
        (guild_id, date, count)
    )
    db.commit()
    return jsonify({"success": True})


# ─────────────────────────────────────────
# SERVE FRONTEND
# ─────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return send_from_directory("static", "dashboard.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
