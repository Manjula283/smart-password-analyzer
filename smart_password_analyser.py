import streamlit as st
import re
import hashlib
import requests
import secrets
import string
import math
from zxcvbn import zxcvbn as zxcvbn_check

st.set_page_config(
    page_title="Smart Password Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
code, .stTextInput input { font-family: 'JetBrains Mono', monospace !important; }
.stApp { background: #0d0f14; color: #e2e8f0; }
h1, h2, h3 { font-family: 'Syne', sans-serif; font-weight: 800; color: #4a9eff !important; }

.metric-card {
    background: #161b27; border: 1px solid #2d3748;
    border-radius: 12px; padding: 20px; margin: 8px 0;
}
.strength-bar-container {
    height: 12px; background: #1e2535;
    border-radius: 6px; overflow: hidden; margin: 10px 0;
}
.strength-bar { height: 100%; border-radius: 6px; }

.factor-row { display: flex; align-items: center; margin: 7px 0; gap: 10px; }
.factor-label {
    font-size: 12px; color: #94a3b8;
    font-family: 'JetBrains Mono', monospace;
    width: 220px; flex-shrink: 0;
}
.factor-bar-bg { flex: 1; height: 8px; background: #1e2535; border-radius: 4px; overflow: hidden; }
.factor-bar-fill { height: 100%; border-radius: 4px; }
.factor-score {
    font-size: 11px; color: #64748b;
    font-family: 'JetBrains Mono', monospace;
    width: 55px; text-align: right; flex-shrink: 0;
}

.tag {
    display: inline-block; padding: 3px 10px; border-radius: 20px;
    font-size: 12px; font-weight: 700; margin: 2px;
    font-family: 'JetBrains Mono', monospace;
}
.tag-upper  { background: #1a3a5c; color: #4a9eff; }
.tag-lower  { background: #1a3a2a; color: #4ade80; }
.tag-digit  { background: #3a2a1a; color: #fb923c; }
.tag-symbol { background: #2a1a3a; color: #c084fc; }
.tag-miss   { background: #2a1a1a; color: #f87171; }

.passphrase-box {
    background: #161b27; border: 1px dashed #4a9eff;
    border-radius: 10px; padding: 14px 18px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 18px; color: #93c5fd; letter-spacing: 1px; margin: 8px 0;
}
.warning-item {
    background: #2a1f0a; border-left: 3px solid #f59e0b;
    padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 5px 0; font-size: 14px;
}
.ok-item {
    background: #0a2a1a; border-left: 3px solid #22c55e;
    padding: 8px 14px; border-radius: 0 8px 8px 0; margin: 5px 0; font-size: 14px;
}
.breach-bad {
    background: #2a0a0a; border-left: 3px solid #ef4444;
    padding: 10px 16px; border-radius: 0 8px 8px 0; font-size: 14px;
}
.suggestion-item {
    background: #161b27; border: 1px solid #2d3748;
    border-radius: 8px; padding: 8px 14px; margin: 4px 0;
    font-size: 13px; color: #94a3b8;
}
.insight-box {
    background: #161b27; border: 1px solid #2d3748;
    border-radius: 10px; padding: 14px 18px; margin: 6px 0;
    font-size: 13px; color: #94a3b8; line-height: 1.9;
}
.crack-fast  { color: #ef4444; font-size: 24px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
.crack-slow  { color: #22c55e; font-size: 24px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
.crack-mid   { color: #f97316; font-size: 24px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
.crack-note  {
    background: #1a2a1a; border-left: 3px solid #22c55e;
    padding: 8px 14px; border-radius: 0 8px 8px 0;
    font-size: 12px; color: #86efac; margin-top: 8px;
}
.crack-warn  {
    background: #2a1f0a; border-left: 3px solid #f59e0b;
    padding: 8px 14px; border-radius: 0 8px 8px 0;
    font-size: 12px; color: #fcd34d; margin-top: 8px;
}

.composition-card {
    background: #161b27; border: 1px solid #2d3748;
    border-radius: 12px; padding: 20px; margin: 8px 0;
}
.comp-bar-track {
    display: flex; height: 18px; border-radius: 9px;
    overflow: hidden; margin: 14px 0 10px 0; gap: 2px;
}
.comp-segment { height: 100%; transition: width 0.4s ease; }
.comp-legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; }
.comp-legend-item {
    display: flex; align-items: center; gap: 6px;
    font-size: 12px; font-family: 'JetBrains Mono', monospace; color: #94a3b8;
}
.comp-dot { width: 10px; height: 10px; border-radius: 50%; }
.comp-stat-row {
    display: flex; justify-content: space-between;
    margin: 5px 0; font-size: 12px; font-family: 'JetBrains Mono', monospace;
}
.comp-stat-label { color: #64748b; }
.comp-stat-val   { font-weight: 700; }
.field-error {
    color: #ef4444; font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    margin-top: -8px; margin-bottom: 4px;
}

footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─── Constants ────────────────────────────────────────────────────────────────
# Source: NordPass Top 200 Most Common Passwords
# https://nordpass.com/most-common-passwords-list/
COMMON_PASSWORDS = {
    # Top 200 from NordPass 2024/2025 research + classic common passwords
    "123456", "123456789", "12345678", "12345", "1234567890",
    "1234567", "password", "000000", "111111", "1234567891",
    "12345678910", "123123", "1234", "password1", "iloveyou",
    "abc123", "qwerty", "qwerty123", "qwertyuiop", "monkey",
    "dragon", "master", "superman", "batman", "football",
    "iloveyou1", "admin", "letmein", "sunshine", "princess",
    "welcome", "shadow", "1q2w3e4r", "1q2w3e", "1q2w3e4r5t",
    "zxcvbnm", "asdfghjkl", "asdfgh", "qazwsx", "qweasdzxc",
    "pass", "pass123", "password123", "test", "test123",
    "guest", "hello", "hello123", "root", "admin123",
    "login", "user", "user123", "default", "changeme",
    "123321", "654321", "987654321", "112233", "121212",
    "123654", "123abc", "1111111", "222222", "333333",
    "444444", "555555", "666666", "777777", "888888",
    "999999", "1111", "2222", "3333", "4444",
    "5555", "6666", "7777", "8888", "9999",
    "11111", "22222", "33333", "44444", "55555",
    "66666", "77777", "88888", "99999", "00000",
    "1111111111", "0000000000", "1234512345", "9876543210",
    "abc", "abcd", "abcde", "abcdef", "abcdefg",
    "abcdefgh", "abcdefghi", "abcdefghij", "aaaaaa", "bbbbbb",
    "cccccc", "dddddd", "eeeeee", "ffffff", "gggggg",
    "zzzzzz", "qqqqqq", "pppppp", "llllll", "kkkkkk",
    "baseball", "soccer", "hockey", "basketball", "tennis",
    "liverpool", "chelsea", "arsenal", "barcelona", "madrid",
    "michael", "jessica", "ashley", "andrew", "joshua",
    "daniel", "david", "george", "charlie", "thomas",
    "jordan", "harley", "ranger", "dakota", "cookie",
    "killer", "matrix", "secret", "cheese", "butter",
    "flower", "purple", "orange", "yellow", "silver",
    "golden", "coffee", "buster", "hunter", "bubbles",
    "wizard", "tigger", "ginger", "pepper", "maggie",
    "access", "mustang", "ferrari", "porsche", "thunder",
    "summer", "winter", "spring", "autumn", "forest",
    "ocean", "mountain", "desert", "valley", "river",
    "falcon", "eagle", "cobra", "viper", "panther",
    "jaguar", "cougar", "thunder", "lightning", "storm",
    "phoenix", "dragon1", "shadow1", "hunter1", "master1",
    "pass1234", "pass12345", "mypass", "mypassword", "passwd",
    "passw0rd", "p@ssword", "p@ss123", "p@ssw0rd", "p@$$word",
    "trustno1", "starwars", "stargate", "pokemon", "pikachu",
    "naruto", "sasuke", "goku", "vegeta", "luffy",
    "ninja", "samurai", "warrior", "viking", "knight",
    "castle", "kingdom", "empire", "republic", "freedom",
    "america", "england", "germany", "france", "canada",
    "india", "china", "japan", "russia", "brazil",
    "love", "love123", "iloveyou2", "lovely", "loveme",
    "family", "friends", "forever", "always", "never",
    "happy", "happy1", "happiness", "smile", "laugh",
    "music", "guitar", "piano", "violin", "drums",
    "apple", "google", "amazon", "facebook", "twitter",
    "instagram", "youtube", "netflix", "spotify", "tiktok",
    "windows", "linux", "ubuntu", "debian", "redhat",
    "python", "java", "javascript", "ruby", "swift",
    "money", "bank", "credit", "debit", "dollar",
    "bitcoin", "crypto", "ethereum", "blockchain", "wallet",
    "qwert", "asdfg", "zxcvb", "poiuy", "lkjhg",
    "09876", "98765", "87654", "76543", "65432",
    "54321", "43210", "password2", "password3", "password4",
    "secret1", "secret123", "private", "hidden", "locked",
    "unlock", "openme", "letme", "letmein1", "enter",
    "system", "network", "server", "database", "admin1234",
    "superuser", "superpass", "rootpass", "sysadmin", "webmaster",
    "skibidi", "pakistan123", "contraseña", "iloveyou3",
}

KEYBOARD_PATTERNS = [
    "qwerty","qwertyui","asdfgh","asdfghjkl","zxcvbn",
    "123456","12345678","abcdef","abcdefgh","qazwsx"
]


# ─── Helpers ──────────────────────────────────────────────────────────────────
def char_breakdown(password):
    return (
        sum(1 for c in password if c.isupper()),
        sum(1 for c in password if c.islower()),
        sum(1 for c in password if c.isdigit()),
        sum(1 for c in password if not c.isalnum()),
    )


def check_breach(password):
    try:
        sha1           = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        res = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5, headers={"Add-Padding": "true"}
        )
        res.raise_for_status()
        for line in res.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except requests.exceptions.Timeout:
        return "timeout"
    except Exception:
        return "error"


def generate_password(length):
    length = max(length, 14)
    for _ in range(100):
        chars = string.ascii_letters + string.digits + "@#$%^&*!?~_-="
        pwd = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("@#$%^&*!?~_-="),
        ]
        pwd += [secrets.choice(chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(pwd)
        result = ''.join(pwd)
        zx = zxcvbn_check(result)
        crack_seconds = float(zx['crack_times_seconds']['offline_fast_hashing_1e10_per_second'])
        if zx['score'] == 4 and crack_seconds > 3.156e13:
            return result
    return result


def generate_passphrase():
    words = [
        "apple","bridge","cloud","dance","eagle","flame","grove","honey",
        "ivory","jungle","kite","lemon","maple","noble","ocean","pearl",
        "quest","river","stone","tiger","ultra","velvet","wheat","xenon",
        "yacht","zebra","amber","blaze","cedar","dusk","ember","frost",
        "gale","haze","iris","jade","karma","lunar","mist","nova",
        "opal","prism","quartz","raven","solar","tide","umbra","vortex"
    ]
    chosen = [secrets.choice(words) for _ in range(4)]
    return f"{'-'.join(chosen)}-{secrets.randbelow(900) + 100}"


def factor_color(score):
    if score < 30: return "#ef4444"
    if score < 55: return "#f97316"
    if score < 75: return "#eab308"
    return                "#22c55e"


def crack_css_class(crack_display):
    fast_keywords = ["seconds to minutes", "minutes to hours", "hours to days",
                     "less than a second", "less than a minute",
                     "second", "seconds", "minute", "minutes", "hour", "hours"]
    mid_keywords  = ["days to weeks", "weeks to months", "months to years",
                     "day", "days", "month", "months", "week", "weeks"]
    txt = crack_display.lower()
    if any(k in txt for k in fast_keywords): return "crack-fast"
    if any(k in txt for k in mid_keywords):  return "crack-mid"
    return "crack-slow"


def has_repeated_segments(password):
    words = re.findall(r'[a-zA-Z]{3,}', password)
    seen = set()
    for w in words:
        wl = w.lower()
        if wl in seen:
            return True, w
        seen.add(wl)
        half = len(wl) // 2
        if half >= 3 and wl[:half] == wl[half:]:
            return True, wl[:half]
    return False, None


def has_repeated_number_segments(password):
    nums = re.findall(r'\d{2,}', password)
    return len(nums) != len(set(nums))


def has_block_repetition(password):
    match = re.search(r'(.)\1{2,}', password)
    if match:
        return True, match.group(0)
    return False, None


def is_word_only(text):
    return bool(re.match(r"^[a-zA-Z\s\-]+$", text.strip())) if text.strip() else True


# ─── L33t speak decoder ───────────────────────────────────────────────────────
LEET_MAP = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i',
    '!': 'i', '0': 'o', '5': 's', '$': 's',
    '7': 't', '+': 't'
}

def deleet(text):
    return ''.join(LEET_MAP.get(c, c) for c in text.lower())


# ─── Entropy-based crack time ─────────────────────────────────────────────────
def _entropy_crack_seconds(password):
    if not password:
        return 1
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    charset = 0
    if has_upper:  charset += 26
    if has_lower:  charset += 26
    if has_digit:  charset += 10
    if has_symbol: charset += 32
    charset = max(charset, 26)
    log_combinations = len(password) * math.log10(charset)
    log_seconds      = log_combinations - 10
    if log_seconds > 20:
        return float('inf')
    return 10 ** log_seconds


def _seconds_to_human(seconds):
    if seconds == float('inf') or seconds > 1e20:
        return "years to centuries"
    MINUTE = 60;  HOUR = 3600;  DAY = 86400
    WEEK   = 604_800; MONTH = 2_592_000; YEAR = 31_536_000
    if seconds < MINUTE:        return "less than a minute"
    if seconds < HOUR:          return "minutes to hours"
    if seconds < DAY:           return "hours to days"
    if seconds < WEEK:          return "days to a week"
    if seconds < MONTH:         return "weeks to a month"
    if seconds < YEAR:          return "months to a year"
    if seconds < YEAR * 10:     return "years to a decade"
    return "years to centuries"


# ─── Adjusted Crack Time ──────────────────────────────────────────────────────
def adjusted_crack_time(final_score, zxcvbn_crack_display, zxcvbn_crack_seconds,
                        pi_matched, seg_repeated, num_repeated, breach_count,
                        password="", zx_score=0):
    if isinstance(breach_count, int) and breach_count > 0:
        return (
            "less than a second",
            "crack-fast",
            f"found in {breach_count:,} real data breaches — hackers already have this password"
        )

    any_repeated = seg_repeated or num_repeated

    if final_score < 25:
        if pi_matched:
            return (
                "less than a second",
                "crack-fast",
                "your personal info is inside the password — targeted attackers try this first"
            )
        return (
            "seconds to minutes",
            "crack-fast",
            "password contains very common or easily guessable patterns"
        )

    if final_score < 50:
        if pi_matched:
            return (
                "minutes to hours",
                "crack-fast",
                "personal info detected — a targeted attacker narrows the search significantly"
            )
        elif any_repeated:
            return (
                "hours to days",
                "crack-mid",
                "repeated word/number pattern detected — hackers use templates to crack these quickly"
            )
        else:
            return (
                "days to a week",
                "crack-mid",
                "no breach found, no personal info — but weak patterns reduce the search space"
            )

    if final_score < 75:
        l = len(password)
        if l < 12:
            crack_str = "months to years"
        elif l < 16:
            crack_str = "years to a decade"
        else:
            crack_str = "years to centuries"
        reason = (
            "no breach found, no personal info — good character mix, "
            "but length limits real-world resistance against GPU-based attacks"
        )
        return (crack_str, crack_css_class(crack_str), reason)

    if zx_score == 4:
        entropy_seconds = _entropy_crack_seconds(password)
        crack_str       = _seconds_to_human(entropy_seconds)
        reason          = "not found in any breach, no personal info, no weak patterns — highly unpredictable"
    else:
        crack_str = _seconds_to_human(zxcvbn_crack_seconds) if zxcvbn_crack_seconds < 1e15 else "years to centuries"
        reason    = "strong password — zxcvbn detected some structure; crack time reflects that"

    return (crack_str, crack_css_class(crack_str), reason)


# ─── Password Composition HTML ────────────────────────────────────────────────
def password_composition_html(password):
    total = len(password)
    if total == 0:
        return ""
    upper, lower, digits, symbol = char_breakdown(password)
    categories = [
        ("Uppercase A–Z", upper,  "#4a9eff", "tag-upper"),
        ("Lowercase a–z", lower,  "#4ade80", "tag-lower"),
        ("Digits 0–9",    digits, "#fb923c", "tag-digit"),
        ("Symbols",       symbol, "#c084fc", "tag-symbol"),
    ]
    bar_html = '<div class="comp-bar-track">'
    for label, count, color, _ in categories:
        if count > 0:
            pct = (count / total) * 100
            bar_html += (
                f'<div class="comp-segment" '
                f'style="width:{pct:.1f}%;background:{color};border-radius:4px;"></div>'
            )
    bar_html += '</div>'
    legend_html = '<div class="comp-legend">'
    for label, count, color, _ in categories:
        pct = (count / total) * 100 if total else 0
        legend_html += (
            f'<div class="comp-legend-item">'
            f'<div class="comp-dot" style="background:{color};"></div>'
            f'{label}: <b style="color:#e2e8f0;">{count}</b> '
            f'<span style="color:#475569;">({pct:.0f}%)</span>'
            f'</div>'
        )
    legend_html += '</div>'
    unique_chars = len(set(password))
    unique_ratio = unique_chars / total if total > 0 else 0
    charset_size = 0
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(not c.isalnum() for c in password): charset_size += 32
    entropy_bits = round(total * math.log2(charset_size), 1) if charset_size > 0 else 0
    entropy_note = " <span style='color:#475569;font-size:10px;'>(theoretical max — actual strength may be lower)</span>"
    unique_ratio_color = "#22c55e" if unique_ratio >= 0.5 else "#ef4444"
    unique_ratio_note  = "" if unique_ratio >= 0.5 else " ⚠️ low"
    stats_html = (
        f'<div class="comp-stat-row">'
        f'<span class="comp-stat-label">Total characters</span>'
        f'<span class="comp-stat-val" style="color:#4a9eff;">{total}</span>'
        f'</div>'
        f'<div class="comp-stat-row">'
        f'<span class="comp-stat-label">Unique characters</span>'
        f'<span class="comp-stat-val" style="color:#c084fc;">{unique_chars}</span>'
        f'</div>'
        f'<div class="comp-stat-row">'
        f'<span class="comp-stat-label">Unique ratio</span>'
        f'<span class="comp-stat-val" style="color:{unique_ratio_color};">'
        f'{unique_ratio:.0%}{unique_ratio_note}</span>'
        f'</div>'
        f'<div class="comp-stat-row">'
        f'<span class="comp-stat-label">Effective entropy (bits)</span>'
        f'<span class="comp-stat-val" style="color:#4ade80;">{entropy_bits}{entropy_note}</span>'
        f'</div>'
        f'<div class="comp-stat-row">'
        f'<span class="comp-stat-label">Character types used</span>'
        f'<span class="comp-stat-val" style="color:#fb923c;">'
        f'{sum(1 for _, c, _, _ in categories if c > 0)} / 4</span>'
        f'</div>'
    )
    return (
        f'<div class="composition-card">'
        f'<div style="font-size:11px;color:#64748b;font-family:JetBrains Mono,monospace;margin-bottom:4px;">PASSWORD COMPOSITION</div>'
        f'{bar_html}{legend_html}'
        f'<div style="border-top:1px solid #2d3748;margin:12px 0 8px 0;"></div>'
        f'{stats_html}</div>'
    )


# ─── Core Analysis ────────────────────────────────────────────────────────────
def analyse(password, personal_info, breach_count):
    factors  = {}
    warnings = []
    p_lower  = password.lower()

    # 1. Length
    l = len(password)
    if   l < 6:  factors["Length"] = 10;  warnings.append("🚫 Too short — minimum 8 characters")
    elif l < 8:  factors["Length"] = 30;  warnings.append("⚠️ Short — aim for 12+ characters")
    elif l < 12: factors["Length"] = 55
    elif l < 16: factors["Length"] = 80
    else:        factors["Length"] = 100

    # 2. Character Variety
    has_upper  = bool(re.search("[A-Z]", password))
    has_lower  = bool(re.search("[a-z]", password))
    has_digit  = bool(re.search("[0-9]", password))
    has_symbol = bool(re.search(r"[@#$%^&*!?~\-_=+\[\](){}|\\/<>.,;:'\"`]", password))
    variety    = sum([has_upper, has_lower, has_digit, has_symbol])
    factors["Character Variety"] = {1: 20, 2: 45, 3: 70, 4: 100}.get(variety, 0)
    if not has_upper:  warnings.append("💡 Add uppercase letters (A–Z)")
    if not has_lower:  warnings.append("💡 Add lowercase letters (a–z)")
    if not has_digit:  warnings.append("💡 Add at least one digit (0–9)")
    if not has_symbol: warnings.append("💡 Add a special character like @, #, !")

    # 3. Common Password
    if password.lower() in COMMON_PASSWORDS:
        factors["Not a Common Password"] = 0
        warnings.append("🚨 Extremely common password — change immediately")
    else:
        factors["Not a Common Password"] = 100

    # 4. Weak Patterns
    penalty = 0
    for kp in KEYBOARD_PATTERNS:
        if kp in p_lower:
            penalty += 40
            warnings.append(f"🚫 Keyboard pattern detected: '{kp}'")
            break
    if re.search(r"(.)\1{2,}", password):
        penalty += 30
        warnings.append("🚫 Repeated characters detected (e.g. aaa, 111) — very guessable")
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde)", p_lower):
        penalty += 25
        warnings.append("🚫 Sequential pattern detected (e.g. 123, abc)")
    seg_repeated, seg_word = has_repeated_segments(password)
    if seg_repeated:
        penalty += 60
        warnings.append(
            f"🚫 Repeated word '{seg_word}' found — despite the length, "
            f"[word][year][word][year] patterns are cracked quickly by targeted attacks"
        )
    num_repeated = has_repeated_number_segments(password)
    if num_repeated:
        penalty += 25
        warnings.append("🚫 Repeated number block — adds length but not real security")

    blk_repeated, blk_example = has_block_repetition(password)
    if blk_repeated:
        penalty += 40
        warnings.append(
            f"🚫 Repeated character block detected (e.g. '{blk_example}') — "
            f"bulk-repeated characters drastically reduce real entropy"
        )

    unique_ratio = len(set(password)) / len(password) if password else 1.0
    if unique_ratio < 0.5:
        penalty += 35
        warnings.append(
            f"🚫 Low character diversity — only {len(set(password))} unique chars in {len(password)} "
            f"({unique_ratio:.0%} unique). Real entropy is much lower than it looks."
        )

    factors["No Weak Patterns"] = max(0, 100 - penalty)

    # 5. Personal Information
    pi_penalty  = 0
    pi_matched  = False
    decoded_pwd = deleet(password)
    labels = ["name", "birth year", "pet name", "city", "custom keyword"]
    for label, info in zip(labels, (personal_info or [])):
        if info and len(info) >= 3:
            info_lower = info.lower()
            in_plain   = info_lower in p_lower
            in_decoded = info_lower in decoded_pwd
            if in_plain or in_decoded:
                pi_penalty += 35
                pi_matched  = True
                leet_note   = " (detected via l33t substitution e.g. @ = a)" if not in_plain else ""
                warnings.append(f"🚫 Contains your {label} '{info}' — hackers try this first{leet_note}")
    if re.search(r"(19|20)\d{2}", password):
        pi_penalty += 20
        warnings.append("⚠️ Contains a year — very predictable")
    factors["No Personal Info"] = max(0, 100 - pi_penalty)

    # 6. zxcvbn
    user_inputs = [i for i in (personal_info or []) if i and i.strip()]
    zx_pi   = zxcvbn_check(password, user_inputs=user_inputs)
    zx_base = zxcvbn_check(password)

    zx_score = zx_pi['score']
    if pi_matched and zx_score > 1:
        zx_score = zx_score - 1

    zx_map = {0: 5, 1: 25, 2: 50, 3: 80, 4: 100}
    factors["Hacker Resistance (zxcvbn)"] = zx_map.get(zx_score, 5)

    fb = zx_pi.get('feedback', {})
    if fb.get('warning'):
        warnings.append(f"⚠️ {fb['warning']}")
    for s in fb.get('suggestions', []):
        warnings.append(f"💡 {s}")

    # Weighted Score
    weights = {
        "Length":                      3,
        "Character Variety":           7,
        "Not a Common Password":       20,
        "No Weak Patterns":            25,
        "No Personal Info":            15,
        "Hacker Resistance (zxcvbn)":  30,
    }
    raw = sum(factors.get(k, 0) * w for k, w in weights.items()) / sum(weights.values())
    raw = round(raw)

    crack_seconds_pi = float(zx_pi['crack_times_seconds']['offline_fast_hashing_1e10_per_second'])
    crack_display_pi = zx_pi['crack_times_display']['offline_fast_hashing_1e10_per_second']

    is_breached = isinstance(breach_count, int) and breach_count > 0

    good_structure = (
        variety == 4 and
        len(password) >= 10 and
        not seg_repeated and
        not num_repeated and
        not blk_repeated and
        unique_ratio >= 0.5 and
        password.lower() not in COMMON_PASSWORDS and
        not is_breached and
        not pi_matched
    )

    if zx_score == 0:
        cap = 55 if good_structure else 24
        raw = min(raw, cap)
    if zx_score == 1:
        cap = 60 if good_structure else 49
        raw = min(raw, cap)
    if zx_score == 2:
        raw = min(raw, 74)
    if pi_matched:
        raw = min(raw, 40)

    if good_structure:
        l = len(password)
        if   l < 12: raw = min(raw, 65)
        elif l < 16: raw = min(raw, 80)

    floor_crack_secs = _entropy_crack_seconds(password) if good_structure else crack_seconds_pi
    if (8 <= len(password) < 12 and variety == 4
            and not seg_repeated
            and password.lower() not in COMMON_PASSWORDS
            and floor_crack_secs >= 3600):
        raw = max(raw, 50)

    is_genuinely_random = (
        variety == 4 and
        unique_ratio >= 0.5 and
        not seg_repeated and
        not num_repeated and
        not blk_repeated and
        not pi_matched and
        not is_breached and
        password.lower() not in COMMON_PASSWORDS and
        len(zx_pi.get('sequence', [])) == 1 and
        zx_pi['sequence'][0].get('pattern') == 'bruteforce'
    )

    if good_structure or is_genuinely_random:
        effective_crack_secs = _entropy_crack_seconds(password)
    else:
        effective_crack_secs = crack_seconds_pi

    if not good_structure:
        if effective_crack_secs < 60:
            raw = min(raw, 24)
            warnings.append("🚨 Crack time under 1 minute — this password is not safe")
        elif effective_crack_secs < 3600:
            raw = min(raw, 40)
            warnings.append("🚨 Crack time under 1 hour — this password is not safe")
        elif effective_crack_secs < 86400:
            raw = min(raw, 60)
            warnings.append("⚠️ Crack time under 1 day — consider a stronger password")
        elif effective_crack_secs < 2592000:
            raw = min(raw, 74)

    if is_breached:
        raw = min(raw, 20)
        factors["Breach Check"] = 0
        warnings.append(f"🚨 Found in {breach_count:,} breaches — strength forced to Very Weak")
    elif breach_count == 0:
        factors["Breach Check"] = 100

    if seg_repeated:
        raw = min(raw, 25)

    if num_repeated:
        raw = min(raw, 35)

    if blk_repeated:
        raw = min(raw, 40)
        warnings.append("🚫 Block repetition detected — score capped at 40")

    if unique_ratio < 0.5:
        raw = min(raw, 45)

    return (factors, warnings, zx_pi, zx_base, raw,
            seg_repeated, seg_word, pi_matched, num_repeated,
            crack_seconds_pi, crack_display_pi, zx_score)


def get_strength_label(score):
    if score < 25: return "Very Weak",  "#ef4444"
    if score < 50: return "Weak",       "#f97316"
    if score < 75: return "Moderate",   "#eab308"
    return               "Strong",      "#22c55e"


# ─── UI ───────────────────────────────────────────────────────────────────────
st.markdown("# 🔐 Smart Password Analyzer")
st.markdown(
    "<p style='color:#64748b;margin-top:-10px;'>"
    "Hacker-realistic scoring · Breach-aware · Real-time analysis · Smart suggestions"
    "</p>", unsafe_allow_html=True
)
st.markdown("---")

with st.sidebar:
    st.markdown("### 👤 Your Personal Info")
    st.caption("Used to detect weak patterns · Word fields only accept letters")

    pi_name = st.text_input("Your name", placeholder="e.g. Manjula")
    if pi_name and not is_word_only(pi_name):
        st.markdown('<div class="field-error">❌ Name must contain letters only — no digits</div>', unsafe_allow_html=True)
        pi_name = ""

    pi_year = st.text_input("Birth year", placeholder="e.g. 2001")
    if pi_year:
        if not re.match(r"^\d{4}$", pi_year.strip()) or not (1900 <= int(pi_year.strip()) <= 2099):
            st.markdown('<div class="field-error">❌ Enter a valid 4-digit year (e.g. 2001)</div>', unsafe_allow_html=True)
            pi_year = ""

    pi_pet = st.text_input("Pet name", placeholder="e.g. Bruno")
    if pi_pet and not is_word_only(pi_pet):
        st.markdown('<div class="field-error">❌ Pet name must contain letters only — no digits</div>', unsafe_allow_html=True)
        pi_pet = ""

    pi_city = st.text_input("City / hometown", placeholder="e.g. Bengaluru")
    if pi_city and not is_word_only(pi_city):
        st.markdown('<div class="field-error">❌ City must contain letters only — no digits</div>', unsafe_allow_html=True)
        pi_city = ""

    pi_custom = st.text_input("Custom keyword", placeholder="e.g. college name")
    if pi_custom and not is_word_only(pi_custom):
        st.markdown('<div class="field-error">❌ Keyword must contain letters only — no digits</div>', unsafe_allow_html=True)
        pi_custom = ""

    personal_info = [pi_name, pi_year, pi_pet, pi_city, pi_custom]

show     = st.checkbox("👁️ Show password as plain text")
password = st.text_input(
    "Enter your password to analyze",
    type="default" if show else "password",
    placeholder="Type your password here..."
)

if password and len(password) < 8:
    st.error("⚠️ Password must be at least 8 characters for basic security!")

if not password:
    st.markdown("""
    <div style="margin-top:40px;text-align:center;color:#334155;">
        <div style="font-size:48px;">🔑</div>
        <p>Enter a password above to see the full analysis</p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

if "last_breach_pwd" not in st.session_state:
    st.session_state["last_breach_pwd"]   = ""
    st.session_state["last_breach_count"] = "unchecked"

if password != st.session_state["last_breach_pwd"]:
    with st.spinner("Checking breach databases..."):
        bc = check_breach(password)
    st.session_state["last_breach_pwd"]   = password
    st.session_state["last_breach_count"] = bc

breach_count = st.session_state["last_breach_count"]

(factors, warnings, zx_result, zx_base, final_score,
 seg_rep, seg_w, pi_matched, num_rep,
 crack_seconds_pi_val, crack_display_pi, zx_score_val) = analyse(password, personal_info, breach_count)

label, color = get_strength_label(final_score)
upper, lower, digits, symbol = char_breakdown(password)

personal_info_set  = any(i.strip() for i in personal_info if i)
crack_display_base = zx_base['crack_times_display']['offline_fast_hashing_1e10_per_second']

crack_display_primary, crack_class, crack_reason = adjusted_crack_time(
    final_score, crack_display_pi, crack_seconds_pi_val,
    pi_matched, seg_rep, num_rep, breach_count,
    password=password, zx_score=zx_score_val
)

# ── Overall Strength + Password Signals ───────────────────────────────────────
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("### 📊 Strength Analysis")
    st.markdown(
        f'<div class="metric-card">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;">'
        f'<span style="font-size:22px;font-weight:800;color:{color};">{label}</span>'
        f'<span style="font-family:JetBrains Mono;color:#64748b;">{final_score}/100</span>'
        f'</div>'
        f'<div class="strength-bar-container">'
        f'<div class="strength-bar" style="width:{final_score}%;background:{color};"></div>'
        f'</div>'
        f'<div style="font-size:11px;color:#475569;margin-top:6px;">'
        f'Score is driven by hacker-realistic checks — repeated patterns, predictability, '
        f'and breach data. Length and character variety alone do NOT make a password strong.'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True
    )

with col2:
    st.markdown("### 📋 Password Signals")
    repeat_flag  = "🚫 Yes — penalized" if seg_rep else "✅ None"
    repeat_color = "#ef4444" if seg_rep else "#22c55e"
    num_rep_flag  = "🚫 Yes — penalized" if num_rep else "✅ None"
    num_rep_color = "#ef4444" if num_rep else "#22c55e"
    unique_ratio_val = len(set(password)) / len(password) if password else 1.0
    ur_color = "#22c55e" if unique_ratio_val >= 0.5 else "#ef4444"
    ur_flag  = f"{unique_ratio_val:.0%}" + ("" if unique_ratio_val >= 0.5 else " ⚠️ low")
    st.markdown(
        f'<div class="metric-card" style="margin-top:8px;">'
        f'<div style="font-size:11px;color:#64748b;font-family:JetBrains Mono,monospace;margin-bottom:10px;">KEY SIGNALS</div>'
        f'<div style="display:flex;justify-content:space-between;margin:8px 0;">'
        f'<span style="font-size:13px;color:#94a3b8;">Length</span>'
        f'<span style="font-size:13px;font-weight:700;color:#4a9eff;">{len(password)} chars</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin:8px 0;">'
        f'<span style="font-size:13px;color:#94a3b8;">Unique Ratio</span>'
        f'<span style="font-size:13px;font-weight:700;color:{ur_color};">{ur_flag}</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin:8px 0;">'
        f'<span style="font-size:13px;color:#94a3b8;">Repeated Word</span>'
        f'<span style="font-size:13px;font-weight:700;color:{repeat_color};">{repeat_flag}</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin:8px 0;">'
        f'<span style="font-size:13px;color:#94a3b8;">Repeated Numbers</span>'
        f'<span style="font-size:13px;font-weight:700;color:{num_rep_color};">{num_rep_flag}</span>'
        f'</div>'
        f'<div style="display:flex;justify-content:space-between;margin:8px 0;">'
        f'<span style="font-size:13px;color:#94a3b8;">Char Types</span>'
        f'<span style="font-size:13px;font-weight:700;color:#c084fc;">{factors.get("Character Variety", 0)}/100</span>'
        f'</div>'
        f'<div style="font-size:11px;color:#475569;margin-top:8px;border-top:1px solid #2d3748;padding-top:8px;">'
        f'Repeated word/numbers = Weak regardless of length.'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True
    )

st.markdown("### 🧩 Score Breakdown by Factor")
st.caption(
    "zxcvbn (30%) + No Weak Patterns (25%) = 55% of your score. "
    "Length is only 3% — a long repeated password will still score Weak."
)

factor_html = '<div class="metric-card">'
for fname, fscore in factors.items():
    fc = factor_color(fscore)
    if   fname == "Hacker Resistance (zxcvbn)": note = " ← 30% weight"
    elif fname == "No Weak Patterns":            note = " ← 25% weight · repetition check"
    elif fname == "Not a Common Password":       note = " ← 20% weight"
    elif fname == "No Personal Info":            note = " ← 15% weight"
    elif fname == "Character Variety":           note = " ← 7% weight"
    elif fname == "Length":                      note = " ← 3% weight only"
    elif fname == "Breach Check":                note = " ← overrides score"
    else:                                        note = ""
    factor_html += (
        f'<div class="factor-row">'
        f'<div class="factor-label">{fname}{note}</div>'
        f'<div class="factor-bar-bg">'
        f'<div class="factor-bar-fill" style="width:{fscore}%;background:{fc};"></div>'
        f'</div>'
        f'<div class="factor-score">{fscore}/100</div>'
        f'</div>'
    )
factor_html += '</div>'
st.markdown(factor_html, unsafe_allow_html=True)

st.markdown("### 🎨 Password Composition")
st.markdown(password_composition_html(password), unsafe_allow_html=True)

col3, col4 = st.columns(2)

with col3:
    st.markdown("### ⏱️ Estimated Crack Time")

    if pi_matched and final_score < 25:
        extra_note = (
            '<div class="crack-warn">'
            '🎯 Your personal info is <b>inside the password</b> — '
            'a targeted attacker tries this first and cracks it <b>instantly</b>.<br><br>'
            f'🌐 <b>Generic attacker</b> (no knowledge of you): <b>{crack_display_base}</b>'
            '</div>'
        )
    elif pi_matched:
        extra_note = (
            '<div class="crack-warn">'
            f'🎯 Personal info detected — crack time reflects <b>targeted</b> attack speed.<br><br>'
            f'🌐 <b>Generic attacker</b> (no knowledge of you): <b>{crack_display_base}</b>'
            '</div>'
        )
    elif not personal_info_set:
        extra_note = (
            '<div class="crack-warn">'
            '💡 Fill in personal info on the left for an accurate targeted attack estimate.'
            '</div>'
        )
    else:
        extra_note = (
            f'<div class="crack-note">'
            f'✅ No personal info found in password.<br>'
            f'🌐 <b>Generic attacker</b>: <b>{crack_display_base}</b>'
            f'</div>'
        )

    st.markdown(
        f'<div class="metric-card" style="text-align:center;">'
        f'<div style="font-size:11px;color:#64748b;font-family:JetBrains Mono,monospace;margin-bottom:6px;">'
        f'TARGETED ATTACKER (knows your personal info)'
        f'</div>'
        f'<div class="{crack_class}">{crack_display_primary}</div>'
        f'<div style="font-size:12px;color:#94a3b8;margin-top:10px;padding:8px 12px;'
        f'background:#1e2535;border-radius:8px;font-style:italic;">'
        f'💬 Why: {crack_reason}'
        f'</div>'
        f'{extra_note}'
        f'</div>',
        unsafe_allow_html=True
    )

with col4:
    st.markdown("### 🕵️ Personal Info Detection")
    pi_hits = [w for w in warnings if any(
        x in w for x in ["name", "birth", "pet", "city", "keyword", "year"]
    )]
    if pi_hits:
        for w in pi_hits:
            st.markdown(f'<div class="warning-item">{w}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="ok-item">✅ No personal patterns detected</div>', unsafe_allow_html=True)

st.markdown("### 🔍 Data Breach Status")
st.caption("Only a partial SHA-1 hash is sent — your password never leaves your machine")

if breach_count == "timeout":
    st.warning("⚠️ Breach check timed out. Score calculated without breach data.")
elif breach_count == "error":
    st.warning("⚠️ Breach API unavailable. Score calculated without breach data.")
elif breach_count == "unchecked":
    st.info("🔄 Checking...")
elif breach_count > 0:
    st.markdown(
        f'<div class="breach-bad">🚨 Found in <strong>{breach_count:,} data breaches</strong>. '
        f'This password is known to hackers — strength score forced to Very Weak.</div>',
        unsafe_allow_html=True
    )
else:
    st.markdown(
        '<div class="ok-item">✅ Not found in any known breach database.</div>',
        unsafe_allow_html=True
    )

zx_score_ui  = zx_result['score']
show_insight = zx_score_ui <= 2 or seg_rep or num_rep

if show_insight:
    st.markdown("### 🧠 Why a Hacker Would Crack This Easily")
    lines = []
    if seg_rep:
        lines.append(
            f"• <b>{seg_w}</b> — repeated word segment. "
            f"Hackers use templates like [name][year][name][year] — "
            f"this is one of the first patterns they try."
        )
    if num_rep:
        nums = re.findall(r'\d{2,}', password)
        lines.append(
            f"• Repeated number block <b>{nums[0]}</b> — "
            f"numeric repetition is a known attack pattern."
        )
    for match in zx_result.get('sequence', []):
        pattern = match.get('pattern', '')
        token   = match.get('token', '')
        if   pattern == 'dictionary': lines.append(f"• <b>{token}</b> — found in name / dictionary list")
        elif pattern == 'date':       lines.append(f"• <b>{token}</b> — recognized as a date or year")
        elif pattern == 'repeat':     lines.append(f"• <b>{token}</b> — repeated character pattern")
        elif pattern == 'sequence':   lines.append(f"• <b>{token}</b> — sequential pattern (123, abc…)")
        elif pattern == 'spatial':    lines.append(f"• <b>{token}</b> — keyboard walk (qwerty…)")
    if lines:
        st.markdown(
            '<div class="insight-box">' + "<br>".join(lines) + '</div>',
            unsafe_allow_html=True
        )

if warnings:
    st.markdown("### 💡 How to Improve")
    seen = set()
    for w in warnings:
        if w not in seen:
            st.markdown(f'<div class="suggestion-item">{w}</div>', unsafe_allow_html=True)
            seen.add(w)

st.markdown("---")
st.markdown(
    "<p style='text-align:center;color:#334155;font-size:13px;'>"
    "Developed by <strong>Manjula</strong> · Cyber Security Project · "
    "Powered by <a href='https://haveibeenpwned.com' style='color:#4a9eff;'>HaveIBeenPwned</a> "
    "& <a href='https://github.com/dwolfhub/zxcvbn-python' style='color:#4a9eff;'>zxcvbn</a>"
    " · Common passwords sourced from "
    "<a href='https://nordpass.com/most-common-passwords-list/' style='color:#4a9eff;'>NordPass Top 200</a>"
    "</p>",
    unsafe_allow_html=True
)