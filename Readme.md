# 🔐 Password Strength Checker

A powerful and secure Python-based command-line tool to evaluate the strength of passwords based on complexity, entropy, and known breached password lists (like RockYou). Ideal for educational purposes, cybersecurity students, and security-conscious developers.

![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

---

## 📋 Features

- ✅ Checks password complexity (length, uppercase, lowercase, digits, symbols)
- 🔐 Calculates entropy based on character pool
- 📚 Checks against:
  - A custom list of common passwords (`common_passwords.txt`)
  - The **RockYou** password list (optional, auto-detects system path)
- 🧠 Provides a human-readable strength rating
- 💡 Suggests improvements for weak passwords
- 🧪 CLI-friendly and portable — no external dependencies

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.6 or higher
- (Optional for RockYou check) On Debian/Ubuntu:
  ```bash
  sudo apt install wordlists
📦 Installation
bash
Copy
Edit
git clone https://github.com/SujalAdhikari-Hacker/Password-Strength-Checker.git
cd password-strength-checker
✅ Ensure the common_passwords.txt file is in the same directory as the script.

🛠 Usage
Option 1: Run and input password interactively
bash
Copy
Edit
python3 password_checker.py
Option 2: Pass password as argument (⚠️ visible in shell history)
bash
Copy
Edit
python3 password_checker.py --password "YourSecureP@ssw0rd!"
🔐 How It Works
Entropy Calculation: Based on character pool size (e.g., uppercase, digits) and password length using Shannon entropy formula.

Complexity Check: Ensures passwords meet standard security criteria.

Wordlist Comparison: Looks for your password in:

common_passwords.txt (local)

rockyou.txt (global, if available)

🧠 Why Use This?
This tool can help you:

Learn about password security and entropy

Educate others in cybersecurity workshops or classrooms

Harden password policies in security awareness programs

Experiment with real-world breached passwords

🧩 To-Do / Ideas
 Add GUI support (Tkinter or PyQt)

 Add zxcvbn-like password pattern analysis

 Add password strength comparison mode

 Export report to JSON or CSV

📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

🙋‍♂️ Author
Sujal Adhikari
Cybersecurity & Digital Forensics Student
🔗 sujaladhikari149.com.np

