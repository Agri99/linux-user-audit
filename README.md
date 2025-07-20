# Linux User & Password Audit Tool
This is a lightweight Python script to audit local Linux user accounts and password configurations.

---

## Features
- Scans /etc/passwd for:
	> Non-root users with UID 0 (dangerous misconfiguration)

	> System accounts with login shells enabled

	> User with sudo privilages
- Scans /etc/shadow for:
	> Accounts without passwords

	> Password Encryption Type
- Skip system accounts (UID < 1000), exept for root

---

## Requirements
- Python 3.x
- colorama : For terminal output styling

---

## How to Run
1. Clone the repository:
'''bash

>git clone https://github.com/Agri99/linux-user-audit.git

>cd linux-user-audit

3. (Optional but recomended) Set up a virtual environment:
'''bash

>python -m venv

>.\venv\Scripts\activate # On Windows

>Source /venv/Script/activate # On Linux

4. Run the script:
'''bash

>sudo python audit.py

---

# Sample Output

Starting Linux User Audit...

Found 4 non-system users

=== User Audit Report ===                                                                                           
----------------------------------------                                                                            
[+] root: OK

[+] nobody: OK

[+] kali: OK

[!] usertest1: Login shell enabled


[+] Auditing user with sudo privilages...

[!] Users with sudo privilages:

     - kali

     - root


Users with UID 0 (root privilages):

     - root



=== Password Audit Report ===                                                                                       
----------------------------------------                                                                            
[+] User Password Encryption:

User: root -> Method: Locked/Invalid -> Strength: Not Usable

User: kali -> Method: yescrypt -> Strength: Very Strong

User: usertest1 -> Method: MD5 -> Strength: Weak


## Version
- v1.0 -> Scanning non-root users with UID 0, accounts with login shell enabled
- v1.1 -> Added feature to scan users with sudo privilages, accounts without password and password encryption type


## Author
Agriana
GitHub: @Agri99

## License
MIT License -- free to use, modify, and distribute.
