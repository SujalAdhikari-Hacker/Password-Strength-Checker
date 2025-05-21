#!/usr/bin/env python3
"""
Password Strength Checker

- Checks password complexity
- Estimates entropy
- Compares against common password and RockYou lists
- Provides strength rating and improvement suggestions
"""

import re
import math
import sys
import os
import platform
import getpass
import argparse

# === Constants ===
ENTROPY_THRESHOLDS = {
    'Very Weak': 28,
    'Weak': 36,
    'Moderate': 60,
    'Strong': 128
}

SPECIAL_CHAR_POOL = 32  # Approximate number of special characters

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMMON_PASSWORDS_FILE = os.path.join(SCRIPT_DIR, 'common_passwords.txt')
ROCKYOU_FILE = '/usr/share/wordlists/rockyou.txt' if platform.system() == 'Linux' else os.path.join(SCRIPT_DIR, 'rockyou.txt')


# === Functions ===

def load_password_list(filepath):
    """Load passwords from a file into a set (lowercase) for quick lookup."""
    passwords = set()
    try:
        with open(filepath, 'r', encoding='latin-1') as file:
            for line in file:
                pw = line.strip().lower()
                if pw:
                    passwords.add(pw)
    except FileNotFoundError:
        print(f"[WARNING] Password list file not found: {filepath}")
        if platform.system() == 'Linux' and 'rockyou.txt' in filepath:
            print("Hint: On Debian/Ubuntu, install with: sudo apt install wordlists")
    except Exception as e:
        print(f"[WARNING] Error loading password list '{filepath}': {e}")
    return passwords


def check_complexity(password):
    """Check password complexity criteria."""
    return (
        len(password) >= 8,
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'\d', password)),
        bool(re.search(r'[^A-Za-z0-9]', password))
    )


def calculate_entropy(password):
    """Estimate entropy based on character pool size and password length."""
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'\d', password): pool += 10
    if re.search(r'[^A-Za-z0-9]', password): pool += SPECIAL_CHAR_POOL
    return round(len(password) * math.log2(pool), 2) if pool else 0


def check_in_password_lists(password, common_passwords, rockyou_passwords):
    """Check if password is in common/rockyou lists."""
    pw_lower = password.lower()
    return pw_lower in common_passwords, pw_lower in rockyou_passwords


def rate_password(entropy, complexity, in_common, in_rockyou):
    """Rate strength based on entropy, complexity, and wordlist presence."""
    length_ok, upper_ok, lower_ok, digit_ok, special_ok = complexity

    # Entropy rating
    if entropy < ENTROPY_THRESHOLDS['Very Weak']:
        rating = 'Very Weak'
    elif entropy < ENTROPY_THRESHOLDS['Weak']:
        rating = 'Weak'
    elif entropy < ENTROPY_THRESHOLDS['Moderate']:
        rating = 'Moderate'
    elif entropy < ENTROPY_THRESHOLDS['Strong']:
        rating = 'Strong'
    else:
        rating = 'Very Strong'

    # Downgrade if in wordlists
    if in_common or in_rockyou:
        rating = 'Weak'

    # Downgrade for complexity issues
    if not length_ok or not lower_ok:
        rating = 'Very Weak'
    elif not (upper_ok and digit_ok and special_ok) and rating == 'Very Strong':
        rating = 'Strong'

    return rating


def generate_feedback(password, complexity, in_common, in_rockyou):
    """Generate feedback based on weaknesses."""
    length_ok, upper_ok, lower_ok, digit_ok, special_ok = complexity
    feedback = []

    if not length_ok: feedback.append("Make your password at least 8 characters long.")
    if not upper_ok: feedback.append("Include uppercase letters (A-Z).")
    if not lower_ok: feedback.append("Include lowercase letters (a-z).")
    if not digit_ok: feedback.append("Add digits (0-9).")
    if not special_ok: feedback.append("Add special characters (e.g., !@#$%).")
    if in_common: feedback.append("Avoid common passwords from your custom list.")
    if in_rockyou: feedback.append("Avoid passwords found in the RockYou breach list.")
    if not feedback: feedback.append("Your password looks strong. Keep it safe!")

    return feedback


def password_strength_report(password):
    """Run checks and return a full strength report as a dictionary."""

    # Load password lists
    common_passwords = load_password_list(COMMON_PASSWORDS_FILE)
    rockyou_passwords = load_password_list(ROCKYOU_FILE)

    # Run checks
    complexity = check_complexity(password)
    entropy = calculate_entropy(password)
    in_common, in_rockyou = check_in_password_lists(password, common_passwords, rockyou_passwords)
    rating = rate_password(entropy, complexity, in_common, in_rockyou)
    feedback = generate_feedback(password, complexity, in_common, in_rockyou)

    # Return dictionary
    return {
        'password': '*' * len(password),
        'length': len(password),
        'entropy': entropy,
        'complexity': {
            'length_ok': complexity[0],
            'upper_ok': complexity[1],
            'lower_ok': complexity[2],
            'digit_ok': complexity[3],
            'special_ok': complexity[4]
        },
        'in_common_list': in_common,
        'in_rockyou_list': in_rockyou,
        'rating': rating,
        'feedback': feedback
    }


def print_report(report):
    """Nicely formatted CLI output."""
    print("\nPassword Strength Checker Report")
    print("-" * 35)
    print(f"Password: {report['password']} (hidden)")
    print(f"Length: {report['length']}")
    print(f"Entropy: {report['entropy']} bits")
    print(f"Complexity Checks:")
    for key, value in report['complexity'].items():
        label = key.replace('_', ' ').capitalize()
        print(f"  - {label}: {'PASS' if value else 'FAIL'}")
    print(f"Common password list check: {'Found' if report['in_common_list'] else 'Not found'}")
    print(f"RockYou list check: {'Found' if report['in_rockyou_list'] else 'Not found'}")
    print(f"\nOverall strength rating: {report['rating']}")
    print("\nSuggestions to improve your password:")
    for advice in report['feedback']:
        print(f" - {advice}")
    print("-" * 35)


def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument('--password', help='Password to check (use with caution - visible in shell history)')
    args = parser.parse_args()

    print("Password Strength Checker")
    print("-" * 30)

    # Use password from CLI or secure input
    password = args.password or getpass.getpass("Enter password to check: ")

    if not password:
        print("No password entered. Exiting.")
        sys.exit(1)

    report = password_strength_report(password)
    print_report(report)


if __name__ == "__main__":
    main()
