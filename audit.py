"""
Linux User and Password Audit Script.

- Parses /etc/passwd and /etc/shadow
- Flags issues like UID 0 misuse, login shell problems, and password format

Author: Agriana
"""

import os # for file operations
from colorama import Fore, Style, init # for colored CLI output


def get_users():
    users = []
    with open("/etc/passwd", "r") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue

            username = parts[0]
            uid = int(parts[2])
            home_dir = parts[5]
            shell = parts[6]

            uid = int(parts[2])
            # Only keep human (non-system) users: UID >= 1000
            # Except root (UID 0), which we still want
            if uid != 0 and uid < 1000:
                continue

            users.append({
                "username": username,
                "uid": uid,
                "home": home_dir,
                "shell": shell
            })

    return users


def analyze_users(users):
    print(Style.BRIGHT + Fore.CYAN + "\n=== User Audit Report ===\n" + "-" * 40)
    for user in users:
        issues = []

        # Check for UID 0 (root-level)
        if user['uid'] == 0 and user['username'] != 'root':
            issues.append("Non-root account with UID 0")

        # Check for login shell set to /bin/bash or others
        if user['shell'] in ["/bin/bash", "/bin/sh"]:
            issues.append("Login shell enabled")

        if issues:
            print(Fore.RED + f"[!] {user['username']}: " + ", ".join(issues))
        else:
            print(Fore.GREEN + f"[+] {user['username']}: OK")


def audit_sudo_users(expected_users=None):
    print("\n[+] Auditing user with sudo privilages...")

    sudo_users = set()

    try:
        with open("/etc/group", "r") as f:
            for line in f:
                if line.startswith("sudo:") or line.startswith("wheel:"):
                    parts = line.strip().split(":")
                    if len(parts) >= 4 and parts[3]:
                        users = parts[3].split(",")
                        sudo_users.update(user.strip() for user in users if user.strip())
        # Add root manually if not present
        sudo_users.add("root")

        if not sudo_users:
            print("[-] No users found in sudo/wheel groups.")
            return

        print("[!] Users with sudo privilages:")
        for user in sorted(sudo_users):
            if expected_users and user not in expected_users:
                print(FORE.YELLOW + f"     - {user} X *(unexpected!)")
            else:
                print(Fore.GREEN + f"     - {user}")

    except Exception as e:
        print(Fore.RED + f"[!] Error while reading /etc/group: {e}")


def audit_uid_0_users():
    try:
        with open("/etc/passwd", "r") as f:
            uid_0_users = []
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2] == "0":
                    uid_0_users.append(parts[0])

        print("\nUsers with UID 0 (root privilages):")
        for user in uid_0_users:
            print(Fore.YELLOW + f"     - {user}")

        if len(uid_0_users) > 1:
            print(Fore.RED + "[!] Warning: More than one user has UID 0!")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to read /etc/passwd: {e}")


def get_encryption_strength(passw):
    if passw.startswith("$6$"):
        return "SHA-512", "Strong"
    elif passw.startswith("$5$"):
        return "SHA-256", "Moderate"
    elif passw.startswith("$1$"):
        return "MD5", "Weak"
    elif passw.startswith(("$2a$", "$2y$")):
        return "bcrypt", "Rare"
    elif passw.startswith("$y$"):
        return "yescrypt", "Very Strong"
    elif passw.startswith("$"):
        return "Unknown", "Encrypted"
    elif passw == "":
        return "Empty", "Insecure"
    else:
        return "Locked/Invalid", "Not Usable"


def audit_encrypted_passwords():
    print(Style.BRIGHT + Fore.CYAN + "\n=== Password Audit Report ===\n" + "-" * 40)
    try:
        print("[+] User Password Encryption:")
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    user, passw = parts[0], parts[1]
                    if user != "root" and not passw.startswith("$"):
                        continue
                    method, strength = get_encryption_strength(passw)
                    if strength:
                        print(f"User: {user} -> Method: {method} -> Strength: {strength}")

    except PermissionError:
        print(Fore.RED + "[!] Permission Denied: Try running with sudo.")
    except Exception as e:
        print(f"[!] Failed to read /etc/shadow: {e}")



def main():
    users = get_users()
    print(f"\nFound {len(users)} non-system users")
    analyze_users(users)
    expected_sudo_users = {"root", "kali"} # Customize this with known safe users on your system
    audit_sudo_users(expected_users=expected_sudo_users)
    audit_uid_0_users()
    audit_encrypted_passwords()

if __name__ == "__main__":
    init(autoreset=True)
    print("Starting Linux User Audit...")
    main()
