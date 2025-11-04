# LSSS - Linux System Security Scanner

A lightweight Bash tool for auditing Linux system security.

## Overview

LSSS scans your system across 14 key security categories, checking configuration, permissions, and vulnerabilities. It's designed for speed, portability, and clarity — no dependencies or setup requiredu.

## Features

* Comprehensive security checks (14 categories)
* Color-coded results (PASS/WARN/SKIP)
* Works on major Linux distributions
* Lightweight (~240 lines) and dependency-free

## Installation

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
* Bash 4.0+
* Standard GNU tools (`grep`, `awk`, `sed`, etc.)

Root privileges recommended for full scan.

## Contributing

1. Fork the repo
2. Create a branch
3. Commit and push your changes
4. Open a Pull Request

Ideas: add new checks, support more distros, improve reports.

## License

MIT License — see the LICENSE file.
