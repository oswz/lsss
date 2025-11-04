# LSSS - Linux System Security Scanner

A lightweight Bash tool for auditing Linux system security.

## Overvie
the script just scan for The Usual Suspects run cmannds that anyone can do but all that in script that about 199 i made it just for my personal use i edit it form now and then add 
## Installatiioni
NOTE: check any script you run in your system you copt form the internet
```bash
git clone https://github.com/oswz/LSSS.git
cd LSSS
chmod +x lsss.sh
```

Or download directly:

```bash
wget https://raw.githubusercontent.com/oswz/LSSS/main/lsss.sh
chmod +x lsss.sh
```

## Usage

```bash
# Basic scan
./lsss.sh

# Full scan (recommended)
sudo ./lsss.sh
```

## Categories Checked

Security frameworks, firewall, SSH, system updates, file permissions, network security, authentication, hardening, logging, services, security tools, boot security, user accounts, and encryption.

## Requirements

* Linux OS
* Bash 
* Standard GNU tools (`grep`, `awk`, `sed`, etc.)

Root privileges recommended for full scan.

## License

MIT License — see the LICENSE file.
