"""
Linux User and Password Audit Script.

- Parses /etc/passwd and /etc/shadow
- Flags issues like UID 0 misuse, login shell problems, and password format

Author: Agriana
"""

import os # for file operations
from colorama import Fore, Style, init # for colored CLI output

init(autoreset=True)

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
    print(Fore.CYAN + "\nUser Audit Report:\n" + "-"*40)
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

def analyze_passwords(users):
    print(Fore.CYAN + "\nPassword Audit Report:\n" + "-" * 40)
    shadow_path = "/etc/shadow"

    try:
        with open(shadow_path, "r") as f:
            shadow_lines = f.readlines()
    except PermissionError:
        print(Fore.RED + "[!] Permission denied reading /etc/shadow. Run as root.")
        return

    shadow_data = {}
    for line in shadow_lines:
        parts = line.strip().split(":")
        if len(parts) >= 2:
            shadow_data[parts[0]] = parts[1] # username : password_hash/flag

    for user in users:
        username = user["username"]
        password_info = shadow_data.get(username)

        if password_info is None:
            print(Fore.RED + f"[!] {username}: No entry in /etc/shadow")
        elif password_info in ["", "!", "!!"]:
            print(Fore.RED + f"[!] {username}: No valid password set")
        elif password_info.startswith("!"):
            if password_info[1:].startswith(("$1$", "$5$", "$6$")):
                print(Fore.Yellow + f"[~] {username}: Account is locked (but has encrypted password)")
            else:
                print(Fore.YELLOW + f"[~] {username}: Account is locked")
        elif password_info.startswith(("*", "!!", "", "x")):
            print(Fore.RED + f"[!] {username}: No valid password set")
        elif password_info.startswith(("$1$", "$5$", "$6$")):
            print(Fore.GREEN + f"[+] Password is set and encrypted")
        else:
            print(Fore.MAGENTA + f"[?] {username}: Unrecognized password field format")

def main():
    users = get_users()
    print(f"\nFound {len(users)} non-system users")
    print(Style.BRIGHT + Fore.CYAN + "\n=== User Audit Report ===")
    analyze_users(users)
    print(Style.BRIGHT + Fore.CYAN + "\n\n=== Password Audit Report ===")
    analyze_passwords(users)

if __name__ == "__main__":
    init(autoreset=True)
    print("Starting Linux User Audit...")
    main()
