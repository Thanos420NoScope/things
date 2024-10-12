#!/bin/bash

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Default values
SKIP_CONFIRM=false
INSTALL_APT_CACHE=false
INSTALL_DOCKER_MIRROR=false
INSTALL_PIHOLE=false
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
LOG_FILE="/var/log/server_setup.log"

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
    echo "Configure a server with various tools and configurations."
    echo
    echo "Options:"
    echo "  -h, --help               Show this help message and exit"
    echo "  -y                       Skip confirmation prompt"
    echo "  --install-apt-cache      Install APT-Cacher NG"
    echo "  --install-docker-mirror  Install Docker Registry Mirror"
    echo "  --install-pihole         Install Pi-hole"
    echo "  --github-user USERNAME   Specify the GitHub username for SSH key addition (required)"
    echo
    echo "Example:"
    echo "  $0 --install-apt-cache --install-docker-mirror --install-pihole --github-user YourGitHubUsername"
}

parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) show_help; exit 0 ;;
            -y) SKIP_CONFIRM=true ;;
            --install-apt-cache) INSTALL_APT_CACHE=true ;;
            --install-docker-mirror) INSTALL_DOCKER_MIRROR=true ;;
            --install-pihole) INSTALL_PIHOLE=true ;;
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
    
    if [ "$INSTALL_APT_CACHE" = true ]; then
        echo -e "${GREEN}$CHECK_MARK${NC} Install APT-Cacher NG"
    else
        echo -e "${RED}$CROSS_MARK${NC} Install APT-Cacher NG"
    fi

    if [ "$INSTALL_DOCKER_MIRROR" = true ]; then
        echo -e "${GREEN}$CHECK_MARK${NC} Install Docker Registry Mirror"
    else
        echo -e "${RED}$CROSS_MARK${NC} Install Docker Registry Mirror"
    fi

    if [ "$INSTALL_PIHOLE" = true ]; then
        echo -e "${GREEN}$CHECK_MARK${NC} Install Pi-hole"
    else
        echo -e "${RED}$CROSS_MARK${NC} Install Pi-hole"
    fi

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

install_apt_cacher_ng() {
    if ! dpkg -s apt-cacher-ng &> /dev/null; then
        log_message "INFO" "Installing APT-Cacher NG..."
        
        echo "apt-cacher-ng apt-cacher-ng/tunnelenable boolean true" | debconf-set-selections
        apt update && DEBIAN_FRONTEND=noninteractive apt install -y apt-cacher-ng || handle_error "Failed to install APT-Cacher NG"
        
        sed -i 's/# PassThroughPattern: .*$/PassThroughPattern: .*/' /etc/apt-cacher-ng/acng.conf
        systemctl enable apt-cacher-ng && systemctl restart apt-cacher-ng
        
        log_message "INFO" "APT-Cacher NG installed and configured."
        log_message "INFO" "Use http://$(hostname -I | awk '{print $1}'):3142 as your APT cache server."
    else
        log_message "INFO" "APT-Cacher NG is already installed."
    fi
}

install_docker_registry_mirror() {
    if ! command -v registry &> /dev/null; then
        log_message "INFO" "Installing Docker Registry Mirror..."
        
        apt update && apt install -y docker.io apache2-utils || handle_error "Failed to install dependencies"
        apt install -y docker-registry || handle_error "Failed to install Docker Registry"
        
        mkdir -p /var/lib/registry
        cat << EOF > /etc/docker/registry/config.yml
version: 0.1
log:
  fields:
    service: registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/docker-registry
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
proxy:
  remoteurl: https://registry-1.docker.io
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
EOF

        systemctl enable docker-registry
        systemctl start docker-registry

        if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
            ufw allow 5000/tcp
        fi

        log_message "INFO" "Docker Registry Mirror installed and configured."
        log_message "INFO" "Use http://$(hostname -I | awk '{print $1}'):5000 as your Docker registry mirror."
    else
        log_message "INFO" "Docker Registry Mirror is already installed."
    fi
}

install_pihole() {
    if ! command -v pihole &> /dev/null; then
        log_message "INFO" "Installing Pi-hole..."
        apt update && apt install -y curl || handle_error "Failed to install curl"
        
        mkdir -p /etc/pihole
        cat << EOF > /etc/pihole/setupVars.conf
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=$(hostname -I | awk '{print $1}')/24
IPV6_ADDRESS=
PIHOLE_DNS_1=94.140.14.14
PIHOLE_DNS_2=94.140.15.15
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=local
WEBPASSWORD=$(openssl rand -base64 48)
BLOCKING_ENABLED=true
EOF

        curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended || handle_error "Failed to install Pi-hole"
        echo "" | sudo pihole -a -p
        systemctl restart pihole-FTL.service

        log_message "INFO" "Pi-hole installed and configured."
        log_message "INFO" "Admin interface available at http://$(hostname -I | awk '{print $1}')/admin"
        log_message "INFO" "Please change the admin password using 'pihole -a -p'"
        log_message "INFO" "Use $(hostname -I | awk '{print $1}') as your DNS server."
    else
        log_message "INFO" "Pi-hole is already installed."
    fi
}

perform_server_setup() {
    log_message "INFO" "Updating and upgrading system packages"
    apt update && apt upgrade -y || handle_error "Failed to update and upgrade system packages"

    log_message "INFO" "Installing essential tools"
    apt install -y docker docker-compose screen git python3.10 python3.10-venv btop htop curl wget fail2ban unattended-upgrades nano ncdu ntp logwatch || handle_error "Failed to install essential tools"

    if ! systemctl is-active --quiet docker; then
        log_message "INFO" "Setting up Docker"
        systemctl enable docker && systemctl start docker || handle_error "Failed to setup Docker"
    fi

    if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        log_message "INFO" "Configuring SSH"
        sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
        systemctl restart sshd || handle_error "Failed to restart SSH service"
    fi

    if [ ! -f /etc/fail2ban/jail.local ]; then
        log_message "INFO" "Configuring fail2ban"
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        systemctl enable fail2ban && systemctl start fail2ban || handle_error "Failed to setup fail2ban"
    fi

    if [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        log_message "INFO" "Enabling automatic security updates"
        dpkg-reconfigure -plow unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    fi

    if [ "$(timedatectl show --property=Timezone --value)" != "America/New_York" ]; then
        log_message "INFO" "Setting timezone to America/New_York"
        timedatectl set-timezone America/New_York || handle_error "Failed to set timezone"
    fi

    if ! grep -q "nofile 65535" /etc/security/limits.conf; then
        log_message "INFO" "Increasing open file limit"
        echo "* soft nofile 65535" >> /etc/security/limits.conf
        echo "* hard nofile 65535" >> /etc/security/limits.conf
    fi

    if ! grep -q "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf; then
        log_message "INFO" "Optimizing system settings"
        cat << EOF >> /etc/sysctl.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65000
net.core.somaxconn = 65535
EOF
        sysctl -p || handle_error "Failed to apply sysctl settings"
    fi

    if [ ! -f ~/.ssh/authorized_keys ] || ! grep -q "github.com/$GITHUB_USER" ~/.ssh/authorized_keys; then
        log_message "INFO" "Adding GitHub keys from user: $GITHUB_USER"
        su - $USER -c "mkdir -p ~/.ssh && curl https://github.com/$GITHUB_USER.keys >> ~/.ssh/authorized_keys" || handle_error "Failed to add GitHub keys"
        chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
    fi

    log_message "INFO" "Performing final system update"
    apt update && apt upgrade -y || handle_error "Failed to perform final system update"

    log_message "INFO" "Server setup complete."
    echo -e "${GREEN}Setup completed successfully.${NC} Please review the log file at $LOG_FILE for details."
}

# Main execution
parse_arguments "$@"
show_summary
confirm_execution

if [ "$INSTALL_APT_CACHE" = true ]; then
    install_apt_cacher_ng
fi

if [ "$INSTALL_DOCKER_MIRROR" = true ]; then
    install_docker_registry_mirror
fi

if [ "$INSTALL_PIHOLE" = true ]; then
    install_pihole
fi

perform_server_setup

exit 0