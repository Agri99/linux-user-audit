# Linux User & Password Audit Tool
This is a lightweight Python script to audit local Linux user accounts and password configurations.

---

## Features
- Scans /etc/passwd for:
	> Non-root users with UID 0 (dangerous misconfiguration)
	> System accounts with login shells enabled
- Scans /etc/shadow for:
	> Accounts without passwords
	> Locked system accounts
	> Invalid password field formats
- Skip system accounts (UID < 1000), exept for root

---

## Requirements
- Python 3.x
- colorama : For terminal output styling

---

## How to Run
1. Clone the repository:
'''bash

git clone
https://github.com/Agri99/linux-user-audit.git
cd linux-user-audit

3. (Optional but recomended) Set up a virtual environment:
'''bash

python -m venv
.\venv\Scripts\activate # On Windows
Source /venv/Script/activate # On Linux

4. Install Required Libraries:
'''bash

pip install -r requirenments.txt

5. Run the script:
'''bash

sudo python audit.py

---

# Sample Output
Starting Linux User Audit...

Found 3 non-system users

=== User Audit Report ===

User Audit Report:
----------------------------------------
[+] root: OK
[+] nobody: OK
[+] kali: OK


=== Password Audit Report ===

Password Audit Report:
----------------------------------------
[!] root: No valid password set
[!] nobody: No valid password set
[!] kali: No valid password set


## Author
Agriana
GitHub: @Agri99

## License
MIT License -- free to use, modify, and distribute.
