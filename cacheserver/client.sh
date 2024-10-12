#!/bin/bash

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Default values
SKIP_CONFIRM=false
APT_CACHE=""
DOCKER_MIRROR=""
PIHOLE_DNS=""
GITHUB_USER=""

# Colors and symbols
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
CHECK_MARK="\xE2\x9C\x94"
CROSS_MARK="\xE2\x9C\x98"
WARNING_MARK="\xE2\x9A\xA0"

# Logging
LOG_FILE="/var/log/client_setup.log"

# Function definitions
log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

handle_error() {
    local error_message=$1
    log_message "ERROR" "$error_message"
    exit 1
}

handle_warning() {
    local warning_message=$1
    log_message "WARNING" "$warning_message"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Configure a client with various tools and services."
    echo
    echo "Options:"
    echo "  -h, --help             Show this help message and exit"
    echo "  -y                     Skip confirmation prompt"
    echo "  --apt-cache SERVER     Use specified APT cache server"
    echo "  --docker-mirror SERVER Use specified Docker registry mirror"
    echo "  --pihole-dns SERVER    Use specified Pi-hole DNS server"
    echo "  --github-user USERNAME Specify the GitHub username for SSH key addition (required)"
    echo
    echo "Example:"
    echo "  $0 --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55:5000 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername"
}

parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) show_help; exit 0 ;;
            -y) SKIP_CONFIRM=true ;;
            --apt-cache) APT_CACHE="$2"; shift ;;
            --docker-mirror) DOCKER_MIRROR="$2"; shift ;;
            --pihole-dns) PIHOLE_DNS="$2"; shift ;;
            --github-user) GITHUB_USER="$2"; shift ;;
            *) echo "Unknown parameter passed: $1"; show_help; exit 1 ;;
        esac
        shift
    done

    if [ -z "$GITHUB_USER" ]; then
        echo "Error: GitHub username is required. Use --github-user USERNAME to specify."
        exit 1
    fi
}

show_summary() {
    clear
    echo "Summary of actions to be performed:"
    
    [ -n "$APT_CACHE" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure APT to use cache server: $APT_CACHE" || echo -e "${RED}$CROSS_MARK${NC} No APT cache server will be configured"
    [ -n "$DOCKER_MIRROR" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure Docker to use registry mirror: $DOCKER_MIRROR" || echo -e "${RED}$CROSS_MARK${NC} No Docker registry mirror will be configured"
    [ -n "$PIHOLE_DNS" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure system to use Pi-hole DNS server: $PIHOLE_DNS" || echo -e "${RED}$CROSS_MARK${NC} No custom DNS server will be configured"
    echo -e "${GREEN}$CHECK_MARK${NC} Update and upgrade system packages"
    echo -e "${GREEN}$CHECK_MARK${NC} Install essential tools (Docker, Git, Python, etc.)"
    echo -e "${GREEN}$CHECK_MARK${NC} Configure SSH (disable password authentication)"
    echo -e "${GREEN}$CHECK_MARK${NC} Set up fail2ban"
    echo -e "${GREEN}$CHECK_MARK${NC} Enable automatic security updates"
    echo -e "${GREEN}$CHECK_MARK${NC} Set timezone to America/New_York"
    echo -e "${GREEN}$CHECK_MARK${NC} Optimize system settings"
    echo -e "${GREEN}$CHECK_MARK${NC} Add GitHub keys from user: $GITHUB_USER"
}

confirm_execution() {
    if [ "$SKIP_CONFIRM" = false ]; then
        echo
        read -p "Do you want to proceed with these actions? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_message "INFO" "Setup cancelled by user."
            exit 0
        fi
    else
        echo -e "\nSkipping confirmation as requested. Proceeding with setup."
    fi
}

configure_apt_cache() {
    if [ -n "$APT_CACHE" ]; then
        log_message "INFO" "Configuring APT to use cache server: $APT_CACHE"
        echo "Acquire::http::Proxy \"http://$APT_CACHE:3142\";" > /etc/apt/apt.conf.d/01proxy
        log_message "INFO" "APT cache configured successfully"
    fi
}

update_upgrade_system() {
    log_message "INFO" "Updating and upgrading system packages"
    apt update || handle_error "Failed to update package lists"
    apt upgrade -y || handle_error "Failed to upgrade packages"
    log_message "INFO" "System packages updated and upgraded successfully"
}

install_essential_tools() {
    log_message "INFO" "Installing essential tools"
    apt install -y docker.io docker-compose git python3.10 python3.10-venv btop htop curl wget fail2ban unattended-upgrades nano ncdu ntp logwatch || handle_error "Failed to install essential tools"
    log_message "INFO" "Essential tools installed successfully"
}

configure_ssh() {
    log_message "INFO" "Configuring SSH"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd || handle_error "Failed to restart SSH service"
    log_message "INFO" "SSH configured successfully"
}

setup_fail2ban() {
    log_message "INFO" "Setting up fail2ban"
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    systemctl enable fail2ban && systemctl start fail2ban || handle_error "Failed to setup fail2ban"
    log_message "INFO" "fail2ban set up successfully"
}

enable_auto_security_updates() {
    log_message "INFO" "Enabling automatic security updates"
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    log_message "INFO" "Automatic security updates enabled"
}

set_timezone() {
    log_message "INFO" "Setting timezone to America/New_York"
    timedatectl set-timezone America/New_York || handle_error "Failed to set timezone"
    log_message "INFO" "Timezone set successfully"
}

optimize_system_settings() {
    log_message "INFO" "Optimizing system settings"
    echo "* soft nofile 65535" >> /etc/security/limits.conf
    echo "* hard nofile 65535" >> /etc/security/limits.conf

    cat << EOF >> /etc/sysctl.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65000
net.core.somaxconn = 65535
EOF
    sysctl -p || handle_error "Failed to apply sysctl settings"
    log_message "INFO" "System settings optimized successfully"
}

add_github_keys() {
    log_message "INFO" "Adding GitHub keys from user: $GITHUB_USER"
    su - $USER -c "mkdir -p ~/.ssh && curl https://github.com/$GITHUB_USER.keys >> ~/.ssh/authorized_keys" || handle_error "Failed to add GitHub keys"
    chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
    log_message "INFO" "GitHub keys added successfully"
}

configure_docker_mirror() {
    if [ -n "$DOCKER_MIRROR" ]; then
        log_message "INFO" "Configuring Docker to use registry mirror: $DOCKER_MIRROR"
        mkdir -p /etc/docker
        echo "{\"registry-mirrors\": [\"http://$DOCKER_MIRROR\"]}" > /etc/docker/daemon.json
        if systemctl is-active --quiet docker; then
            systemctl restart docker || handle_warning "Failed to restart Docker after mirror configuration. Please restart Docker manually."
        else
            handle_warning "Docker service is not running. Please start Docker and apply the new configuration."
        fi
        log_message "INFO" "Docker registry mirror configured successfully"
    fi
}

configure_pihole_dns() {
    if [ -n "$PIHOLE_DNS" ]; then
        log_message "INFO" "Configuring system to use Pi-hole DNS server: $PIHOLE_DNS"
        if systemctl is-active --quiet systemd-resolved; then
            sed -i '/^#*DNS=/c\DNS='"$PIHOLE_DNS" /etc/systemd/resolved.conf
            sed -i '/^#*DNSStubListener=/c\DNSStubListener=no' /etc/systemd/resolved.conf
            systemctl restart systemd-resolved || handle_error "Failed to restart systemd-resolved"
            ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
            log_message "INFO" "DNS configuration completed using systemd-resolved"
        else
            echo "nameserver $PIHOLE_DNS" | tee /etc/resolv.conf > /dev/null
            log_message "INFO" "DNS configuration completed by updating /etc/resolv.conf directly"
        fi
        log_message "INFO" "Pi-hole DNS configured successfully"
    fi
}

# Main execution
parse_arguments "$@"
show_summary
confirm_execution

configure_apt_cache
update_upgrade_system
install_essential_tools
configure_ssh
setup_fail2ban
enable_auto_security_updates
set_timezone
optimize_system_settings
add_github_keys
configure_docker_mirror
configure_pihole_dns

log_message "INFO" "Client setup complete"
echo -e "${GREEN}Setup completed successfully.${NC} Please review the log file at $LOG_FILE for details."

exit 0