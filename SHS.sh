#!/bin/bash
#this script is made by aa it's just point out some basic security 
BOLD=$(tput bold); RED=$(tput setaf 1); GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4); NORMAL=$(tput sgr0)
clear
echo "${BOLD}${BLUE}================================================"
echo "    Linux System Security Scan  - by AA"
echo "================================================${NORMAL}"


WARNINGS=0; PASSED=0; SKIPPED=0

log() {
    case "$2" in
        PASS) echo "[${GREEN}${BOLD}PASS${NORMAL}] ($1) $3"; ((PASSED++));;
        WARN) echo "[${RED}${BOLD}WARN${NORMAL}] ($1) $3"; ((WARNINGS++));;
        INFO) echo "[${BLUE}${BOLD}INFO${NORMAL}] $3";;
        SKIP) echo "[${YELLOW}${BOLD}SKIP${NORMAL}] ($1) $3"; ((SKIPPED++));;
    esac
}

[ "$(id -u)" -ne 0 ] && log "" INFO "Not running as root - some checks may fail"

distro=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
log "" INFO "Distribution: $distro | Kernel: $(uname -r)"
echo ""

echo "${BOLD}${BLUE}[1] Security Frameworks${NORMAL}"
if command -v sestatus &>/dev/null; then
    [[ $(sestatus | grep "SELinux status:" | awk '{print $3}') == "enabled" ]] && \
        log "SELinux" PASS "Enabled" || log "SELinux" WARN "Not enabled"
elif command -v apparmor_status &>/dev/null; then
    apparmor_status | grep -q "apparmor module is loaded" && \
        log "AppArmor" PASS "Enabled" || log "AppArmor" WARN "Not enabled"
else
    log "Security" WARN "No SELinux/AppArmor found"
fi

echo ""
echo "${BOLD}${BLUE}[2] Firewall${NORMAL}"
if command -v ufw &>/dev/null && [[ $(ufw status 2>/dev/null | grep -o "active") == "active" ]]; then
    log "Firewall" PASS "UFW active"
elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    log "Firewall" PASS "Firewalld active"
elif command -v iptables &>/dev/null && [ "$(iptables -L | grep -v "^Chain\|^target\|^$" | wc -l)" -gt 0 ]; then
    log "Firewall" PASS "Iptables configured"
else
    log "Firewall" WARN "No active firewall"
fi

echo ""
echo "${BOLD}${BLUE}[3] SSH Configuration${NORMAL}"
if [ -f /etc/ssh/sshd_config ]; then
    root_login=$(grep "^PermitRootLogin " /etc/ssh/sshd_config | awk '{print $2}')
    [[ "$root_login" =~ ^(no|prohibit-password)$ ]] && \
        log "SSH" PASS "Root login disabled" || log "SSH" WARN "Root login enabled"
    
    pass_auth=$(grep "^PasswordAuthentication " /etc/ssh/sshd_config | awk '{print $2}')
    [[ "$pass_auth" == "no" ]] && \
        log "SSH" PASS "Password auth disabled" || log "SSH" WARN "Password auth enabled"
else
    log "SSH" SKIP "Not installed"
fi

echo ""
echo "${BOLD}${BLUE}[4] System Updates${NORMAL}"
case "$distro" in
    fedora|centos|rhel)
        updates=$(dnf check-update -q 2>/dev/null | grep -v "^$" | wc -l)
        [ "$updates" -eq 0 ] && log "Updates" PASS "Up-to-date" || \
            log "Updates" WARN "$updates packages need updating";;
    ubuntu|debian)
        apt update -qq &>/dev/null
        updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing" | wc -l)
        [ "$updates" -eq 0 ] && log "Updates" PASS "Up-to-date" || \
            log "Updates" WARN "$updates packages need updating";;
    *) log "Updates" SKIP "Unknown distribution";;
esac

echo ""
echo "${BOLD}${BLUE}[5] Critical File Permissions${NORMAL}"
check_perm() {
    [ -f "$1" ] && {
        perm=$(stat -c '%a' "$1")
        [ "$perm" -le "$2" ] && log "Perms" PASS "$1 secure ($perm)" || \
            log "Perms" WARN "$1 insecure ($perm)"
    }
}
check_perm /etc/passwd 644
check_perm /etc/shadow 400
check_perm /etc/group 644

echo ""
echo "${BOLD}${BLUE}[6] Network Security${NORMAL}"
[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ] && \
    log "Network" PASS "IP forwarding disabled" || log "Network" WARN "IP forwarding enabled"

[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ] && \
    log "Network" PASS "SYN cookies enabled" || log "Network" WARN "SYN cookies disabled"

[ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = "0" ] && \
    log "Network" PASS "ICMP redirects disabled" || log "Network" WARN "ICMP redirects enabled"

echo ""
echo "${BOLD}${BLUE}[7] Authentication${NORMAL}"
if [ -f /etc/security/pwquality.conf ]; then
    minlen=$(grep -Po '^minlen\s*=\s*\K\d+' /etc/security/pwquality.conf 2>/dev/null)
    [ -n "$minlen" ] && [ "$minlen" -ge 8 ] && \
        log "Password" PASS "Min length: $minlen" || log "Password" WARN "Weak password policy"
else
    log "Password" WARN "pwquality.conf not found"
fi

empty_pass=$(cut -d: -f1,2 /etc/shadow 2>/dev/null | grep '::' | cut -d: -f1)
[ -z "$empty_pass" ] && log "Password" PASS "No empty passwords" || \
    log "Password" WARN "Empty passwords found: $empty_pass"

echo ""
echo "${BOLD}${BLUE}[8] System Hardening${NORMAL}"
aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
[ "$aslr" = "2" ] && log "System" PASS "ASLR fully enabled" || \
    log "System" WARN "ASLR not fully enabled"

grep -qE "flags.*(pae|nx)" /proc/cpuinfo 2>/dev/null && \
    log "System" PASS "NX/DEP supported" || log "System" WARN "NX/DEP not supported"

echo ""
echo "${BOLD}${BLUE}[9] Logging & Auditing${NORMAL}"
systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog 2>/dev/null && \
    log "Logging" PASS "Syslog active" || log "Logging" WARN "No syslog service"

command -v auditd &>/dev/null && systemctl is-active --quiet auditd && \
    log "Audit" PASS "Auditd active" || log "Audit" WARN "Auditd not active"

echo ""
echo "${BOLD}${BLUE}[10] System Services${NORMAL}"
for svc in telnet vsftpd rsh-server; do
    ! systemctl is-active --quiet "$svc" 2>/dev/null && \
        log "Services" PASS "$svc not running" || log "Services" WARN "$svc running"
done

echo ""
echo "${BOLD}${BLUE}[11] Security Tools${NORMAL}"
command -v rkhunter &>/dev/null && log "Tools" PASS "rkhunter installed" || \
    log "Tools" WARN "rkhunter not installed"
command -v aide &>/dev/null && log "Tools" PASS "AIDE installed" || \
    log "Tools" WARN "AIDE not installed"

echo ""
echo "${BOLD}${BLUE}[12] Boot Security${NORMAL}"
if [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
    grep -q "password" /boot/grub*/grub.cfg 2>/dev/null && \
        log "Boot" PASS "GRUB password set" || log "Boot" WARN "No GRUB password"
fi

if command -v mokutil &>/dev/null; then
    mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled" && \
        log "Boot" PASS "Secure Boot enabled" || log "Boot" WARN "Secure Boot disabled"
else
    log "Boot" SKIP "Cannot check Secure Boot"
fi

echo ""
echo "${BOLD}${BLUE}[13] User Accounts${NORMAL}"
root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
[ "$root_users" = "root" ] && log "Users" PASS "Only root has UID 0" || \
    log "Users" WARN "Multiple UID 0: $root_users"

if [ -f /etc/sudoers ]; then
    [ "$(stat -c '%a' /etc/sudoers)" -eq 440 ] && \
        log "Users" PASS "Sudoers perms secure" || log "Users" WARN "Sudoers perms insecure"
    
    ! grep -qr "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null && \
        log "Users" PASS "No NOPASSWD in sudoers" || log "Users" WARN "NOPASSWD found"
fi

echo ""
echo "${BOLD}${BLUE}[14] Encryption${NORMAL}"
if command -v openssl &>/dev/null; then
    openssl ciphers -v 2>/dev/null | grep -qi "TLSv1.3" && \
        log "Crypto" PASS "TLS 1.3 supported" || log "Crypto" WARN "TLS 1.3 not supported"
else
    log "Crypto" SKIP "OpenSSL not installed"
fi

echo ""
echo "${BOLD}${BLUE}================================================${NORMAL}"
echo "${BOLD}${GREEN}Scan Complete${NORMAL}"
echo "Passed: ${GREEN}$PASSED${NORMAL} | Warnings: ${RED}$WARNINGS${NORMAL} | Skipped: ${YELLOW}$SKIPPED${NORMAL}"
echo "${BOLD}${BLUE}================================================${NORMAL}"

echo ""
echo "${BOLD}recommendations:${NORMAL}"
echo "1. Address all warnings per your security policy"
echo "2. Run regular security audits"
echo "3. Review CIS Benchmarks for $distro"
echo "4. Keep system updated and patched"

exit 0
