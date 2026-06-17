# 🔐 Smart Password Policy Checker

> A hacker-realistic password strength analyzer built with Python and Streamlit.  
> Goes beyond basic rules — detects real-world attack patterns, checks breach databases, and scores passwords the way a hacker would evaluate them.

---

## ✨ Features

- **Hacker-realistic scoring** — not just length/complexity checks
- **HaveIBeenPwned API** integration using k-anonymity (password never sent in full)
- **zxcvbn** library for pattern-based strength estimation
- **Personal info detection** — name, birth year, pet name, city, custom keyword
- **L33t speak decoder** — catches substitutions like `@` → `a`, `3` → `e`
- **Top 200 common passwords** blacklist (sourced from NordPass)
- **Keyboard pattern detection** — qwerty, asdfgh, etc.
- **Repeated word/number segment detection**
- **Adjusted crack time estimation** — targeted attacker vs generic attacker
- **Password Composition visualizer** — entropy bits, unique ratio, character breakdown
- **Strong password & passphrase generator**
- Real-time analysis with smart improvement suggestions

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core logic |
| Streamlit | Web UI framework |
| zxcvbn | Pattern-based strength estimation |
| HaveIBeenPwned API | Breach database check (k-anonymity) |
| hashlib | SHA-1 hashing for breach lookup |
| secrets | Secure password generation |
| re / math | Pattern detection & entropy calculation |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/smart-password-policy-checker.git
cd smart-password-policy-checker

# Install dependencies
pip install streamlit zxcvbn requests

# Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`

---

## 📁 Project Structure

```
smart-password-policy-checker/
│
├── app.py               # Main Streamlit application
├── requirements.txt     # Python dependencies
└── README.md
```

### requirements.txt
```
streamlit
zxcvbn
requests
```

---

## 🔒 How the Breach Check Works

This tool uses the **HaveIBeenPwned Pwned Passwords API** with **k-anonymity**:

1. Your password is hashed using SHA-1
2. Only the **first 5 characters** of the hash are sent to the API
3. The API returns all matching hash suffixes
4. The comparison happens **locally** — your full password never leaves your machine

---

## 📊 Scoring Weights

| Factor | Weight |
|---|---|
| Hacker Resistance (zxcvbn) | 30% |
| No Weak Patterns | 25% |
| Not a Common Password | 20% |
| No Personal Info | 15% |
| Character Variety | 7% |
| Length | 3% |
| Breach Check | Overrides score |

> ⚠️ A long password with repeated patterns will still score **Weak** — length alone doesn't mean strength.

---

## 💡 What Makes This Different

Most password checkers just count character types and length. This tool:

- Detects **word repetition** (e.g. `Manjula2001Manjula2001`)
- Catches **personal info** even with l33t substitutions (e.g. `M@njul@`)
- Uses **real breach data** — if hackers already have it, score is forced to Very Weak
- Adjusts crack time for **targeted attackers** who know your personal info
- Uses **entropy-based crack time** for genuinely random passwords

---

## 👩‍💻 Developed By

**Manjula** · B.E. Electronics & Communication Engineering  
Cyber Security Internship Capstone Project  
GSSS Institute of Engineering and Technology for Women, Mysore

---

## Acknowledgements

- [HaveIBeenPwned](https://haveibeenpwned.com) — Troy Hunt's breach database
- [zxcvbn](https://github.com/dwolfhub/zxcvbn-python) — Dropbox's password strength estimator
- [NordPass Top 200](https://nordpass.com/most-common-passwords-list/) — Common passwords list
