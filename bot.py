"""
SentinelHQ Discord Bot (v2 - with backend integration)
pip install discord.py aiohttp python-dotenv
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
import aiohttp
import asyncio
import json
import os
import re
from datetime import datetime, timezone
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()

DISCORD_TOKEN  = os.getenv("DISCORD_TOKEN")
VPNAPI_KEY     = os.getenv("VPNAPI_KEY", "")
WEBHOOK_URL    = os.getenv("BACKEND_URL", "http://localhost:5000")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-this-secret")

MIN_ACCOUNT_AGE_DAYS = 30
ALT_CONFIDENCE_HIGH  = 85
ALT_CONFIDENCE_MED   = 60

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)
guild_data = defaultdict(lambda: {"log_channel": None})

# ─────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────

def account_age_days(member):
    return (datetime.now(timezone.utc) - member.created_at).days

def risk_score(member, past_names):
    score = 0
    reasons = []
    age = account_age_days(member)

    if age < 1:
        score += 40; reasons.append("Account created less than 24 hours ago")
    elif age < 7:
        score += 25; reasons.append(f"Account is only {age} day(s) old")
    elif age < 30:
        score += 10; reasons.append(f"Account is {age} days old")

    name_lower = member.name.lower()
    for old in past_names:
        if name_lower in old.lower() or old.lower() in name_lower:
            if name_lower != old.lower():
                score += 35
                reasons.append(f"Username similar to: {old}")
                break

    alt_patterns = [r'\d{4,}$', r'_?v\d+$', r'_alt\d*$', r'new\d*$', r'2024$', r'2025$']
    for p in alt_patterns:
        if re.search(p, member.name, re.IGNORECASE):
            score += 15; reasons.append(f"Alt-like username pattern detected"); break

    return min(score, 100), reasons

async def post_to_backend(endpoint, data):
    """Send data to the Flask backend."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{WEBHOOK_URL}{endpoint}",
                json=data,
                headers={"X-Sentinel-Secret": WEBHOOK_SECRET},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                return resp.status == 200
    except Exception as e:
        print(f"[Backend Post Error] {endpoint}: {e}")
        return False

async def check_vpn(ip):
    if not VPNAPI_KEY or not ip:
        return {}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}", timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    d = await r.json()
                    sec = d.get("security", {})
                    loc = d.get("location", {})
                    net = d.get("network", {})
                    return {
                        "is_vpn":   sec.get("vpn", False),
                        "is_proxy": sec.get("proxy", False),
                        "is_tor":   sec.get("tor", False),
                        "provider": net.get("autonomous_system_organization", "Unknown"),
                        "country":  loc.get("country", "Unknown"),
                    }
    except: pass
    return {}

def fmt_embed(title, desc, color, fields=None):
    e = discord.Embed(title=title, description=desc, color=color, timestamp=datetime.now(timezone.utc))
    e.set_footer(text="SentinelHQ")
    if fields:
        for n, v, i in fields: e.add_field(name=n, value=v, inline=i)
    return e

async def get_log_ch(guild):
    cid = guild_data[guild.id]["log_channel"]
    return guild.get_channel(cid) if cid else None

# ─────────────────────────────────────────
# EVENTS
# ─────────────────────────────────────────

@bot.event
async def on_ready():
    print(f"[SentinelHQ] Online as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"[SentinelHQ] {len(synced)} commands synced")
    except Exception as e:
        print(f"[Sync Error] {e}")
    daily_snapshot.start()

@bot.event
async def on_member_join(member):
    guild = member.guild
    existing = [m.name for m in guild.members if m.id != member.id]
    score, reasons = risk_score(member, existing)
    age = account_age_days(member)
    log_ch = await get_log_ch(guild)

    # Post to backend dashboard
    await post_to_backend("/webhook/member_join", {
        "guild_id": str(guild.id),
        "user_id":  str(member.id),
        "username": str(member),
        "score":    score,
        "reasons":  reasons,
        "is_vpn":   False,  # VPN check needs IP from verification flow
    })

    if score >= ALT_CONFIDENCE_MED or age < 7:
        color  = discord.Color.red() if score >= ALT_CONFIDENCE_HIGH else discord.Color.orange()
        status = "🚨 HIGH RISK" if score >= ALT_CONFIDENCE_HIGH else "⚠️ SUSPICIOUS"
        embed  = fmt_embed(
            f"{status} — Member Joined",
            f"{member.mention} joined.",
            color,
            fields=[
                ("User",        f"{member} (`{member.id}`)", True),
                ("Account Age", f"{age} day(s)",             True),
                ("Risk Score",  f"{score}/100",               True),
                ("Reasons",     "\n".join(f"• {r}" for r in reasons) or "None", False),
            ]
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        if log_ch: await log_ch.send(embed=embed)
    elif log_ch:
        embed = fmt_embed("✅ Member Joined", f"{member.mention} — Age: {age}d — Risk: {score}/100", discord.Color.green())
        await log_ch.send(embed=embed)

@bot.event
async def on_member_remove(member):
    log_ch = await get_log_ch(member.guild)
    if log_ch:
        await log_ch.send(embed=fmt_embed("📤 Member Left", f"**{member}** left.", discord.Color.greyple()))

@bot.event
async def on_member_ban(guild, user):
    log_ch = await get_log_ch(guild)
    if log_ch:
        await log_ch.send(embed=fmt_embed("🔨 Banned", f"**{user}** (`{user.id}`) was banned.", discord.Color.red()))

# ─────────────────────────────────────────
# TASKS
# ─────────────────────────────────────────

@tasks.loop(hours=24)
async def daily_snapshot():
    for guild in bot.guilds:
        await post_to_backend("/webhook/member_count", {
            "guild_id": str(guild.id),
            "count":    guild.member_count,
        })

# ─────────────────────────────────────────
# SLASH COMMANDS
# ─────────────────────────────────────────

@bot.tree.command(name="setup", description="Set alert log channel")
@app_commands.describe(channel="Channel for alerts")
@app_commands.checks.has_permissions(administrator=True)
async def setup(interaction, channel: discord.TextChannel):
    guild_data[interaction.guild.id]["log_channel"] = channel.id
    await interaction.response.send_message(
        embed=fmt_embed("✅ Setup Done", f"Alerts → {channel.mention}", discord.Color.green()),
        ephemeral=True
    )

@bot.tree.command(name="stats", description="Server statistics")
async def stats(interaction):
    guild = interaction.guild
    await guild.chunk()
    total  = guild.member_count
    bots   = sum(1 for m in guild.members if m.bot)
    online = sum(1 for m in guild.members if m.status != discord.Status.offline and not m.bot)
    new7   = sum(1 for m in guild.members if account_age_days(m) < 7 and not m.bot)
    await interaction.response.send_message(embed=fmt_embed(
        f"📊 {guild.name}",
        f"Dashboard: {WEBHOOK_URL}/dashboard",
        discord.Color.blurple(),
        fields=[
            ("👥 Members", str(total),  True),
            ("🟢 Online",  str(online), True),
            ("🤖 Bots",    str(bots),   True),
            ("🆕 <7 days", str(new7),   True),
        ]
    ))

@bot.tree.command(name="userinfo", description="Risk analysis on a member")
@app_commands.describe(member="Member to check")
async def userinfo(interaction, member: discord.Member):
    existing = [m.name for m in interaction.guild.members if m.id != member.id]
    score, reasons = risk_score(member, existing)
    age = account_age_days(member)
    color   = discord.Color.red() if score >= 85 else discord.Color.orange() if score >= 60 else discord.Color.green()
    verdict = "🚨 HIGH RISK" if score >= 85 else "⚠️ SUSPICIOUS" if score >= 60 else "✅ SAFE"
    await interaction.response.send_message(embed=fmt_embed(
        f"User Info — {member}",
        f"**{verdict}** — {score}/100",
        color,
        fields=[
            ("ID",          str(member.id),                                       False),
            ("Account Age", f"{age} days (Created {member.created_at.strftime('%b %d, %Y')})", True),
            ("Joined",      member.joined_at.strftime('%b %d, %Y') if member.joined_at else "?", True),
            ("Reasons",     "\n".join(f"• {r}" for r in reasons) or "None",      False),
        ]
    ))

@bot.tree.command(name="sentinel_help", description="All commands")
async def sentinel_help(interaction):
    await interaction.response.send_message(embed=fmt_embed(
        "🛡️ SentinelHQ Commands",
        f"Dashboard: {WEBHOOK_URL}",
        discord.Color.blurple(),
        fields=[
            ("/setup #ch",       "Set log channel",          False),
            ("/stats",           "Server overview",          False),
            ("/userinfo @user",  "Risk check a member",      False),
            ("/sentinel_help",   "This message",             False),
        ]
    ), ephemeral=True)

@bot.tree.error
async def on_error(interaction, error):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message("❌ No permission.", ephemeral=True)
    else:
        await interaction.response.send_message(f"❌ Error: {error}", ephemeral=True)

if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("[ERROR] DISCORD_TOKEN missing in .env")
        exit(1)
    bot.run(DISCORD_TOKEN)
