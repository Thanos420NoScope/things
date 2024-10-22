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
APT_CACHE_PORT=8000
DOCKER_MIRROR_PORT=8001
TIMEZONE="America/New_York"

# Colors and formatting
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
CHECK_MARK="\xE2\x9C\x94"
CROSS_MARK="\xE2\x9C\x98"
WARNING_MARK="\xE2\x9A\xA0"

# Logging setup
LOG_FILE="/var/log/client_setup.log"
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

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
    echo "  --timezone TIMEZONE    Set the timezone (default: America/New_York)"
    echo
    echo "Example:"
    echo "  $0 --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername"
}

parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) show_help; exit 0 ;;
            -y) SKIP_CONFIRM=true ;;
            --apt-cache) 
                APT_CACHE="$2"
                if [ -z "$APT_CACHE" ]; then
                    handle_error "APT cache server cannot be empty"
                fi
                shift ;;
            --docker-mirror)
                DOCKER_MIRROR="$2"
                if [ -z "$DOCKER_MIRROR" ]; then
                    handle_error "Docker mirror server cannot be empty"
                fi
                shift ;;
            --pihole-dns)
                PIHOLE_DNS="$2"
                if [ -z "$PIHOLE_DNS" ]; then
                    handle_error "Pi-hole DNS server cannot be empty"
                fi
                shift ;;
            --github-user) 
                GITHUB_USER="$2"
                if [ -z "$GITHUB_USER" ]; then
                    handle_error "GitHub username cannot be empty"
                fi
                shift ;;
            --timezone)
                TIMEZONE="$2"
                if [ -z "$TIMEZONE" ]; then
                    handle_error "Timezone cannot be empty"
                fi
                shift ;;
            *) echo "Unknown parameter passed: $1"; show_help; exit 1 ;;
        esac
        shift
    done

    if [ -z "$GITHUB_USER" ]; then
        handle_error "GitHub username is required. Use --github-user USERNAME to specify."
    fi
}

configure_ufw() {
    log_message "INFO" "Configuring UFW firewall..."
    
    # Install UFW if not already installed
    apt install -y ufw || handle_error "Failed to install UFW"
    
    # Reset UFW to default state
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (always required)
    ufw allow in 22/tcp
    
    # Allow established connections
    ufw allow established

    # Enable UFW
    ufw --force enable
    
    # Show status
    ufw status verbose
    
    log_message "INFO" "UFW configuration completed"
}

show_summary() {
    clear
    echo "Summary of actions to be performed:"
    
    [ -n "$APT_CACHE" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure APT to use cache server: $APT_CACHE:$APT_CACHE_PORT" || echo -e "${RED}$CROSS_MARK${NC} No APT cache server will be configured"
    [ -n "$DOCKER_MIRROR" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure Docker to use registry mirror: $DOCKER_MIRROR:$DOCKER_MIRROR_PORT" || echo -e "${RED}$CROSS_MARK${NC} No Docker registry mirror will be configured"
    [ -n "$PIHOLE_DNS" ] && echo -e "${GREEN}$CHECK_MARK${NC} Configure system to use Pi-hole DNS server: $PIHOLE_DNS" || echo -e "${RED}$CROSS_MARK${NC} No custom DNS server will be configured"
    echo -e "${GREEN}$CHECK_MARK${NC} Configure UFW firewall"
    echo -e "${GREEN}$CHECK_MARK${NC} Update and upgrade system packages"
    echo -e "${GREEN}$CHECK_MARK${NC} Install essential tools (Docker, Git, Python, etc.)"
    echo -e "${GREEN}$CHECK_MARK${NC} Configure SSH (disable password authentication)"
    echo -e "${GREEN}$CHECK_MARK${NC} Set up fail2ban"
    echo -e "${GREEN}$CHECK_MARK${NC} Enable automatic security updates"
    echo -e "${GREEN}$CHECK_MARK${NC} Set timezone to $TIMEZONE"
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
        log_message "INFO" "Configuring APT cache..."
        
        # Create apt configuration file for the cache
        cat << EOF > /etc/apt/apt.conf.d/00apt-cacher-ng
Acquire::http::Proxy "http://${APT_CACHE}:${APT_CACHE_PORT}";
Acquire::https::Proxy "false";
EOF
        
        # Test the connection to APT cache
        if ! curl -s "http://${APT_CACHE}:${APT_CACHE_PORT}" >/dev/null; then
            handle_warning "Could not connect to APT cache server. Check if it's running and accessible."
        else
            log_message "INFO" "APT cache configured successfully"
        fi
    else
        log_message "INFO" "No APT cache server specified, skipping configuration"
    fi
}

configure_docker_mirror() {
    if [ -n "$DOCKER_MIRROR" ]; then
        log_message "INFO" "Configuring Docker registry mirror..."
        
        # Ensure Docker is installed
        if ! command -v docker >/dev/null 2>&1; then
            handle_error "Docker is not installed. Please install Docker first."
        fi
        
        # Create docker daemon configuration directory if it doesn't exist
        mkdir -p /etc/docker
        
        # Create or update daemon.json with registry mirror configuration
        cat << EOF > /etc/docker/daemon.json
{
    "registry-mirrors": ["http://${DOCKER_MIRROR}:${DOCKER_MIRROR_PORT}"]
}
EOF
        
        # Restart Docker service to apply changes
        systemctl restart docker || handle_error "Failed to restart Docker service"
        
        # Test the Docker mirror
        if ! curl -s "http://${DOCKER_MIRROR}:${DOCKER_MIRROR_PORT}/v2/" >/dev/null; then
            handle_warning "Could not connect to Docker registry mirror. Check if it's running and accessible."
        else
            log_message "INFO" "Docker registry mirror configured successfully"
        fi
    else
        log_message "INFO" "No Docker registry mirror specified, skipping configuration"
    fi
}

configure_pihole_dns() {
    if [ -n "$PIHOLE_DNS" ]; then
        log_message "INFO" "Configuring Pi-hole DNS..."
        
        # Backup original resolv.conf
        cp /etc/resolv.conf /etc/resolv.conf.backup
        
        # Configure systemd-resolved to use Pi-hole
        cat << EOF > /etc/systemd/resolved.conf
[Resolve]
DNS=${PIHOLE_DNS}
#Domains=~.
#DNSSEC=no
#DNSOverTLS=no
#MulticastDNS=no
#LLMNR=no
Cache=no
DNSStubListener=no
EOF
        
        # Restart systemd-resolved
        systemctl restart systemd-resolved || handle_error "Failed to restart systemd-resolved"
        
        # Update resolv.conf to use Pi-hole
        echo "nameserver ${PIHOLE_DNS}" > /etc/resolv.conf
        
        # Test DNS resolution
        if ! ping -c 1 google.com >/dev/null 2>&1; then
            handle_warning "DNS resolution test failed. Check if Pi-hole is working correctly."
        else
            log_message "INFO" "Pi-hole DNS configured successfully"
        fi
    else
        log_message "INFO" "No Pi-hole DNS server specified, skipping configuration"
    fi
}

install_essential_tools() {
    log_message "INFO" "Installing essential tools"
    
    # Update package list
    apt update || handle_error "Failed to update package lists"
    
    # Install packages
    DEBIAN_FRONTEND=noninteractive apt install -y \
        docker.io \
        docker-compose \
        git \
        python3.10 \
        python3.10-venv \
        btop \
        htop \
        curl \
        wget \
        fail2ban \
        unattended-upgrades \
        nano \
        ncdu \
        logwatch \
        build-essential \
        g++ \
        make \
        ufw || handle_error "Failed to install essential tools"
    
    # Enable Docker service
    systemctl enable docker
    systemctl start docker
    
    log_message "INFO" "Essential tools installed successfully"
}

configure_ssh() {
    log_message "INFO" "Configuring SSH"
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Configure SSH
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    
    # Restart SSH service
    systemctl restart sshd || handle_error "Failed to restart SSH service"
    
    log_message "INFO" "SSH configured successfully"
}

setup_fail2ban() {
    log_message "INFO" "Setting up fail2ban"
    
    # Copy default configuration
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Configure fail2ban to work with UFW
    cat << EOF > /etc/fail2ban/jail.d/custom.conf
[DEFAULT]
banaction = ufw
findtime = 10m
bantime = 24h
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
EOF
    
    # Enable and restart fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban || handle_error "Failed to restart fail2ban"
    
    log_message "INFO" "fail2ban configured successfully"
}

enable_auto_security_updates() {
    log_message "INFO" "Enabling automatic security updates"
    
    # Configure unattended-upgrades service
    sudo DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    
    log_message "INFO" "Automatic security updates enabled"
}

set_timezone() {
    log_message "INFO" "Setting timezone to $TIMEZONE"
    
    # Verify timezone exists
    if ! timedatectl list-timezones | grep -q "^$TIMEZONE$"; then
        handle_error "Invalid timezone: $TIMEZONE"
        return 1
    fi
    
    # Set timezone
    if ! timedatectl set-timezone "$TIMEZONE"; then
        handle_error "Failed to set timezone"
        return 1
    fi

    log_message "INFO" "Timezone set successfully to $TIMEZONE"
    return 0
}

optimize_system_settings() {
    log_message "INFO" "Optimizing system settings"
    
    # Backup sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup
    
    # Configure system limits
    cat << EOF > /etc/security/limits.d/custom.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

    # Configure sysctl settings
    cat << EOF > /etc/sysctl.d/99-custom.conf
# Increase system file descriptor limit
fs.file-max = 100000

# Increase system IP port range
net.ipv4.ip_local_port_range = 1024 65535

# Increase TCP max buffer size
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Enable TCP fast open
net.ipv4.tcp_fastopen = 3

# Optimize TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65536

# TCP connection optimization
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0

# VM memory management
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF
    
    # Apply sysctl changes
    sysctl -p /etc/sysctl.d/99-custom.conf || handle_warning "Some sysctl parameters might not have been applied"
    
    log_message "INFO" "System settings optimized"
}

add_github_keys() {
    log_message "INFO" "Adding GitHub SSH keys for user: $GITHUB_USER"
    
    # Create .ssh directory if it doesn't exist
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Backup existing authorized_keys if it exists
    [ -f ~/.ssh/authorized_keys ] && cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup
    
    # Download GitHub keys
    if ! curl -sf "https://github.com/$GITHUB_USER.keys" > ~/.ssh/authorized_keys.new; then
        handle_error "Failed to fetch GitHub keys for user: $GITHUB_USER"
    fi
    
    # Check if any keys were downloaded
    if [ ! -s ~/.ssh/authorized_keys.new ]; then
        handle_error "No SSH keys found for GitHub user: $GITHUB_USER"
    fi
    
    # Move new keys into place
    mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys
    
    # Set proper permissions
    chmod 600 ~/.ssh/authorized_keys
    
    log_message "INFO" "GitHub SSH keys added successfully"
}

perform_final_checks() {
    log_message "INFO" "Performing final system checks..."
    
    # Check SSH configuration
    if ! sshd -t; then
        handle_warning "SSH configuration test failed"
    fi
    
    # Check UFW status
    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW firewall is not active"
    fi
    
    # Check fail2ban status
    if ! systemctl is-active --quiet fail2ban; then
        handle_warning "fail2ban is not running"
    fi
    
    # Check Docker status
    if ! systemctl is-active --quiet docker; then
        handle_warning "Docker is not running"
    fi
    
    # Test DNS resolution if Pi-hole is configured
    if [ -n "$PIHOLE_DNS" ]; then
        if ! ping -c 1 google.com >/dev/null 2>&1; then
            handle_warning "DNS resolution test failed"
        fi
    fi
    
    log_message "INFO" "Final system checks completed"
}

cleanup() {
    log_message "INFO" "Performing cleanup..."
    
    # Remove unnecessary packages
    apt autoremove -y
    apt clean
    
    # Clear system logs if they're too large
    if [ -f /var/log/syslog ] && [ "$(stat -f --format="%s" /var/log/syslog)" -gt 1048576 ]; then
        truncate -s 0 /var/log/syslog
    fi
    
    # Clear journal logs older than 3 days
    journalctl --vacuum-time=3d
    
    log_message "INFO" "Cleanup completed"
}

# Main execution
parse_arguments "$@"
show_summary
confirm_execution

# Perform setup tasks
configure_apt_cache
update_upgrade_system() {
    log_message "INFO" "Updating and upgrading system packages"
    apt update || handle_error "Failed to update package lists"
    apt upgrade -y || handle_error "Failed to upgrade packages"
    log_message "INFO" "System packages updated and upgraded successfully"
}
install_essential_tools
configure_ufw
configure_ssh
setup_fail2ban
enable_auto_security_updates
set_timezone
optimize_system_settings
add_github_keys
configure_docker_mirror
configure_pihole_dns

# Perform final tasks
perform_final_checks
cleanup

log_message "INFO" "Client setup complete"
echo -e "${GREEN}Setup completed successfully.${NC} Please review the log file at $LOG_FILE for details."

# Display important information
if [ -n "$APT_CACHE" ]; then
    echo -e "\nAPT Cache Server: http://$APT_CACHE:$APT_CACHE_PORT"
fi
if [ -n "$DOCKER_MIRROR" ]; then
    echo -e "Docker Registry Mirror: http://$DOCKER_MIRROR:$DOCKER_MIRROR_PORT"
fi
if [ -n "$PIHOLE_DNS" ]; then
    echo -e "Pi-hole DNS Server: $PIHOLE_DNS"
fi

echo -e "\nImportant Note: Please reboot the system to ensure all changes take effect."

exit 0
