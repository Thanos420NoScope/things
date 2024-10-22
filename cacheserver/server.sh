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
INSTALL_GIT_CACHE=false
GITHUB_USER=""
GITHUB_TOKEN=""
GIT_CACHE_DIR="/var/cache/git-cache"
APT_CACHE_PORT=8000
DOCKER_MIRROR_PORT=8001
PIHOLE_WEB_PORT=8002
GIT_CACHE_PORT=8003
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
LOG_FILE="/var/log/server_setup.log"
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
    echo "Configure a server with various tools and services."
    echo
    echo "Options:"
    echo "  -h, --help                Show this help message and exit"
    echo "  -y                        Skip confirmation prompt"
    echo "  --install-apt-cache       Install APT-Cacher NG"
    echo "  --install-docker-mirror   Install Docker Registry Mirror"
    echo "  --install-pihole          Install Pi-hole"
    echo "  --install-git-cache       Install Git Proxy Cache"
    echo "  --github-user USERNAME    Specify the GitHub username for SSH key addition (required)"
    echo "  --github-token TOKEN      Specify the GitHub token for release script (required)"
    echo "  --timezone TIMEZONE       Set the timezone (default: America/New_York)"
    echo
    echo "Example:"
    echo "  $0 --install-apt-cache --install-docker-mirror --install-pihole --install-git-cache --github-user YourGitHubUsername --github-token YourGitHubToken"
}

parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help) show_help; exit 0 ;;
            -y) SKIP_CONFIRM=true ;;
            --install-apt-cache) INSTALL_APT_CACHE=true ;;
            --install-docker-mirror) INSTALL_DOCKER_MIRROR=true ;;
            --install-pihole) INSTALL_PIHOLE=true ;;
            --install-git-cache) INSTALL_GIT_CACHE=true ;;
            --github-user) 
                GITHUB_USER="$2"
                if [ -z "$GITHUB_USER" ]; then
                    handle_error "GitHub username cannot be empty"
                fi
                shift ;;
            --github-token)
                GITHUB_TOKEN="$2"
                if [ -z "$GITHUB_TOKEN" ]; then
                    handle_error "GitHub token cannot be empty"
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
    
    if [ -z "$GITHUB_TOKEN" ]; then
        handle_error "GitHub token is required. Use --github-token TOKEN to specify."
    fi
}

configure_ufw() {
    log_message "INFO" "Configuring UFW firewall..."
    
    # Install UFW
    apt install -y ufw || handle_error "Failed to install UFW"
    
    # Reset UFW to default state
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (always required)
    ufw allow 22/tcp
    
    # Allow established connections
    ufw allow established
    
    # Allow required ports based on installed services
    if [ "$INSTALL_APT_CACHE" = true ]; then
        ufw allow $APT_CACHE_PORT/tcp
    fi
    
    if [ "$INSTALL_DOCKER_MIRROR" = true ]; then
        ufw allow $DOCKER_MIRROR_PORT/tcp
    fi
    
    if [ "$INSTALL_PIHOLE" = true ]; then
        # Pi-hole DNS ports
        ufw allow 53/tcp
        ufw allow 53/udp
        # Pi-hole web interface
        ufw allow $PIHOLE_WEB_PORT/tcp
        # Pi-hole FTL
        ufw allow 4711/tcp
    fi
    
    if [ "$INSTALL_GIT_CACHE" = true ]; then
        ufw allow $GIT_CACHE_PORT/tcp
    fi
    
    # Enable UFW
    ufw --force enable
    
    # Show status
    ufw status verbose
    
    log_message "INFO" "UFW configuration completed"
}

show_summary() {
    clear
    echo "Summary of actions to be performed:"
    
    [ "$INSTALL_APT_CACHE" = true ] && echo -e "${GREEN}$CHECK_MARK${NC} Install APT-Cacher NG (Port: $APT_CACHE_PORT)" || echo -e "${RED}$CROSS_MARK${NC} Skip APT-Cacher NG"
    [ "$INSTALL_DOCKER_MIRROR" = true ] && echo -e "${GREEN}$CHECK_MARK${NC} Install Docker Registry Mirror (Port: $DOCKER_MIRROR_PORT)" || echo -e "${RED}$CROSS_MARK${NC} Skip Docker Registry Mirror"
    [ "$INSTALL_PIHOLE" = true ] && echo -e "${GREEN}$CHECK_MARK${NC} Install Pi-hole (Web Port: $PIHOLE_WEB_PORT, DNS: 53)" || echo -e "${RED}$CROSS_MARK${NC} Skip Pi-hole"
    [ "$INSTALL_GIT_CACHE" = true ] && echo -e "${GREEN}$CHECK_MARK${NC} Install Git Proxy Cache (Port: $GIT_CACHE_PORT)" || echo -e "${RED}$CROSS_MARK${NC} Skip Git Proxy Cache"
    echo -e "${GREEN}$CHECK_MARK${NC} Configure UFW firewall"
    echo -e "${GREEN}$CHECK_MARK${NC} Update and upgrade system packages"
    echo -e "${GREEN}$CHECK_MARK${NC} Install essential tools"
    echo -e "${GREEN}$CHECK_MARK${NC} Configure SSH (disable password authentication)"
    echo -e "${GREEN}$CHECK_MARK${NC} Set up fail2ban"
    echo -e "${GREEN}$CHECK_MARK${NC} Enable automatic security updates"
    echo -e "${GREEN}$CHECK_MARK${NC} Set timezone to $TIMEZONE"
    echo -e "${GREEN}$CHECK_MARK${NC} Optimize system settings"
    echo -e "${GREEN}$CHECK_MARK${NC} Add GitHub keys from user: $GITHUB_USER"
    echo -e "${GREEN}$CHECK_MARK${NC} Set up release script with GitHub token"
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
    log_message "INFO" "Installing APT-Cacher NG..."
    
    # Install APT-Cacher NG
    echo "apt-cacher-ng apt-cacher-ng/tunnelenable boolean true" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt install -y apt-cacher-ng || handle_error "Failed to install APT-Cacher NG"

    # Create cache directory with proper permissions
    mkdir -p /var/cache/apt-cacher-ng
    chown -R apt-cacher-ng:apt-cacher-ng /var/cache/apt-cacher-ng
    
    # Enable and start service
    systemctl enable apt-cacher-ng || handle_error "Failed to enable APT-Cacher NG"
    systemctl start apt-cacher-ng || handle_error "Failed to start APT-Cacher NG"

    # Configure and restart
    echo "Port: ${APT_CACHE_PORT}" >> /etc/apt-cacher-ng/acng.conf
    sed -i 's/# PassThroughPattern: .*$/PassThroughPattern: .*/' /etc/apt-cacher-ng/acng.conf
    systemctl restart apt-cacher-ng || handle_error "Failed to restart APT-Cacher NG"
    
    # Verify service is running
    if ! systemctl is-active --quiet apt-cacher-ng; then
        handle_error "APT-Cacher NG service failed to start"
    fi
    
    log_message "INFO" "APT-Cacher NG installed and configured on port $APT_CACHE_PORT"
}

install_docker_registry_mirror() {
    log_message "INFO" "Installing Docker Registry Mirror..."

    # Create registry directories
    mkdir -p /var/lib/docker-registry

    # Create Docker registry configuration
    mkdir -p /etc/docker/registry
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
  addr: :$DOCKER_MIRROR_PORT
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
    
    # Create systemd service for Docker registry
    cat << EOF > /etc/systemd/system/docker-registry.service
[Unit]
Description=Docker Registry Mirror
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/bin/docker run --restart=always -p $DOCKER_MIRROR_PORT:5000 \
    -v /var/lib/docker-registry:/var/lib/registry \
    -v /etc/docker/registry/config.yml:/etc/docker/registry/config.yml \
    registry:2

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and start services
    systemctl daemon-reload
    systemctl enable docker-registry
    systemctl start docker-registry
    sleep 3
    systemctl restart docker-registry
    log_message "INFO" "Docker Registry Mirror installed and configured on port $DOCKER_MIRROR_PORT"
}

install_pihole() {
    log_message "INFO" "Installing Pi-hole..."

    # Prepare Pi-hole configuration
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
WEBUIBOXEDLAYOUT=boxed
WEBTHEME=default-darker
DNSSEC=true
REV_SERVER=false
EOF
    
    # Install Pi-hole
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended || handle_error "Failed to install Pi-hole"
    
    # Configure custom web port
    sed -i "s/^\s*server.port\s*=.*/server.port = $PIHOLE_WEB_PORT/" /etc/lighttpd/lighttpd.conf
    
    # Restart services
    systemctl restart lighttpd
    pihole restartdns
    
    # Remove password
    echo "" | sudo pihole -a -p

    # Verify installation
    if ! command -v pihole >/dev/null 2>&1; then
        handle_error "Pi-hole installation failed"
    fi
    
    log_message "INFO" "Pi-hole installed and configured"
    log_message "INFO" "Web interface available at: http://$(hostname -I | awk '{print $1}'):$PIHOLE_WEB_PORT/admin"
}

install_git_cache() {
    log_message "INFO" "Installing Git Cache (Gitea)..."

    # Create Gitea user
    useradd -r -m -d /home/gitea gitea

    # Download and install Gitea
    wget -O /usr/local/bin/gitea https://dl.gitea.io/gitea/1.19.0/gitea-1.19.0-linux-amd64
    chmod +x /usr/local/bin/gitea

    # Create necessary directories
    mkdir -p /var/lib/gitea/{custom,data,log,repos}
    mkdir -p $GIT_CACHE_DIR
    chown -R gitea:gitea $GIT_CACHE_DIR
    chown -R gitea:gitea /var/lib/gitea
    chmod -R 750 /var/lib/gitea
    mkdir -p /etc/gitea
    chown root:gitea /etc/gitea
    chmod 770 /etc/gitea

    # Setup SSH directory
    mkdir -p /home/gitea/.ssh
    chown -R gitea:gitea /home/gitea/.ssh
    chmod 700 /home/gitea/.ssh

    # Get the local IP address
    LOCAL_IP=$(hostname -I | awk '{print $1}')

    # Configure Gitea
    cat << EOF > /etc/gitea/app.ini
[database]
DB_TYPE = sqlite3
PATH = /var/lib/gitea/data/gitea.db

[server]
HTTP_PORT = ${GIT_CACHE_PORT}
ROOT_URL = http://${LOCAL_IP}:${GIT_CACHE_PORT}/
PROTOCOL = http
DOMAIN = ${LOCAL_IP}
SSH_DOMAIN = ${LOCAL_IP}
START_SSH_SERVER = false
OFFLINE_MODE = false

[repository]
ROOT = ${GIT_CACHE_DIR}
ENABLE_PRIVATE_REPO = false
DEFAULT_MIRROR = true
DEFAULT_PRIVATE = false
DEFAULT_PUSH_CREATE_PRIVATE = false
MIGRATION_CLONE_DEFAULT = true

[security]
INSTALL_LOCK = true
SECRET_KEY = $(openssl rand -base64 32)
INTERNAL_TOKEN = $(openssl rand -base64 32)
MIN_PASSWORD_LENGTH = 6

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false

[session]
PROVIDER = file
PROVIDER_CONFIG = data/sessions

[picture]
DISABLE_GRAVATAR = true
ENABLE_FEDERATED_AVATAR = false

[admin]
DEFAULT_EMAIL_NOTIFICATIONS = false

[cron]
ENABLED = true
REPO_MIGRATION_UPDATE_INTERVAL = 30m

[mirror]
DEFAULT_INTERVAL = 30m

[log]
MODE = console
LEVEL = Info
ROOT_PATH = /var/lib/gitea/log
EOF

    # Create systemd service
    cat << EOF > /etc/systemd/system/gitea.service
[Unit]
Description=Gitea (Git Cache Server)
After=syslog.target
After=network.target

[Service]
RestartSec=2s
Type=simple
User=gitea
Group=gitea
WorkingDirectory=/var/lib/gitea/
ExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini
Restart=always
Environment=USER=gitea HOME=/home/gitea GITEA_WORK_DIR=/var/lib/gitea

[Install]
WantedBy=multi-user.target
EOF

    # Set proper permissions
    chown gitea:gitea /etc/gitea/app.ini
    chmod 640 /etc/gitea/app.ini

    # Start and enable Gitea
    systemctl daemon-reload
    systemctl enable gitea
    systemctl start gitea || handle_error "Failed to start Gitea service"

    # Create admin user
    sleep 5
    su - gitea -s /bin/bash -c "gitea admin user create --username root --password password --email admin@example.com --admin --must-change-password=false --config /etc/gitea/app.ini"

    # Verify Gitea is running
    if ! curl -s "http://localhost:$GIT_CACHE_PORT/" > /dev/null; then
        handle_error "Gitea failed to start properly"
    fi

    log_message "INFO" "Gitea installed and configured on port $GIT_CACHE_PORT"
}

install_essential_tools() {
    log_message "INFO" "Installing essential tools"
    
    # Update package list
    apt update && apt upgrade -y || handle_error "Failed to update package lists"
    
    # Install packages
    DEBIAN_FRONTEND=noninteractive apt install -y \
        apache2-utils \
        docker.io \
        docker-compose \
        docker-registry \
        screen \
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
        sqlite3 \
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
    
    # Configure fail2ban
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

setup_release_script() {
    log_message "INFO" "Setting up release script..."
    
    # Download the release script
    wget -O /root/release.py https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/release.py || handle_error "Failed to download release script"
    chmod +x /root/release.py || handle_error "Failed to make release script executable"
    
    # Add cron job
    (crontab -l 2>/dev/null; echo "*/30 * * * * cd /root && python3 release.py -t $GITHUB_TOKEN") | crontab - || handle_error "Failed to add cron job"
    
    log_message "INFO" "Release script setup completed"
}

perform_final_checks() {
    log_message "INFO" "Performing final system checks..."
    
    # Check installed services
    local services=()
    [ "$INSTALL_APT_CACHE" = true ] && services+=("apt-cacher-ng")
    [ "$INSTALL_DOCKER_MIRROR" = true ] && services+=("docker-registry")
    [ "$INSTALL_PIHOLE" = true ] && services+=("pihole-FTL")
    [ "$INSTALL_GIT_CACHE" = true ] && services+=("gitea")
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            handle_warning "Service $service is not running"
        fi
    done
    
    # Check UFW status
    if ! ufw status | grep -q "Status: active"; then
        handle_warning "UFW firewall is not active"
    fi
    
    # Check fail2ban status
    if ! systemctl is-active --quiet fail2ban; then
        handle_warning "fail2ban is not running"
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

# Configure base system
install_essential_tools
configure_ufw
configure_ssh
setup_fail2ban
enable_auto_security_updates
set_timezone
optimize_system_settings
add_github_keys

# Install selected services
[ "$INSTALL_APT_CACHE" = true ] && install_apt_cacher_ng
[ "$INSTALL_DOCKER_MIRROR" = true ] && install_docker_registry_mirror
[ "$INSTALL_PIHOLE" = true ] && install_pihole
[ "$INSTALL_GIT_CACHE" = true ] && install_git_cache

# Setup release script
setup_release_script

# Final tasks
perform_final_checks
cleanup

# Function to check if a service is running
check_service() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}[OK]${NC} $1 is running"
    else
        echo -e "${RED}[FAIL]${NC} $1 is not running"
    fi
}

# Function to check if a port is open
check_port() {
    if nc -z localhost $1; then
        echo -e "${GREEN}[OK]${NC} Port $1 is open"
    else
        echo -e "${RED}[FAIL]${NC} Port $1 is closed"
    fi
}

# Test APT-Cacher NG
echo "Testing APT-Cacher NG..."
check_service apt-cacher-ng
check_port $APT_CACHE_PORT

# Test Docker Registry Mirror
echo -e "\nTesting Docker Registry Mirror..."
check_service docker-registry
check_port $DOCKER_MIRROR_PORT

# Test Pi-hole
echo -e "\nTesting Pi-hole..."
check_service pihole-FTL
check_service lighttpd
check_port 53  # DNS port
check_port $PIHOLE_WEB_PORT

# Test Gitea (Git cache)
echo -e "\nTesting Gitea (Git cache)..."
check_service gitea
check_port $GIT_CACHE_PORT

# Test Docker
echo -e "\nTesting Docker..."
check_service docker

# Test fail2ban
echo -e "\nTesting fail2ban..."
check_service fail2ban

# Test unattended-upgrades
echo -e "\nTesting unattended-upgrades..."
if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "ok installed"; then
    echo -e "${GREEN}[OK]${NC} unattended-upgrades is installed"
else
    echo -e "${RED}[FAIL]${NC} unattended-upgrades is not installed"
fi

# Check sysctl settings
echo -e "\nChecking sysctl settings..."
if sysctl net.ipv4.tcp_syncookies | grep -q "= 1"; then
    echo -e "${GREEN}[OK]${NC} Sysctl settings are configured correctly"
else
    echo -e "${RED}[FAIL]${NC} Sysctl settings are not configured correctly"
fi

# Check essential packages
echo -e "\nChecking essential packages..."
PACKAGES="git python3.10 python3.10-venv btop htop curl wget nano ncdu logwatch build-essential g++ make"
for pkg in $PACKAGES; do
    if dpkg-query -W -f='${Status}' $pkg 2>/dev/null | grep -q "ok installed"; then
        echo -e "${GREEN}[OK]${NC} $pkg is installed"
    else
        echo -e "${RED}[FAIL]${NC} $pkg is not installed"
    fi
done

# Check SSH configuration
echo -e "\nChecking SSH configuration..."
if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
    echo -e "${GREEN}[OK]${NC} SSH password authentication is disabled"
else
    echo -e "${RED}[FAIL]${NC} SSH password authentication is not disabled"
fi

echo -e "\nServer test completed."

# Display service information
echo -e "\n${GREEN}Server setup completed successfully${NC}"
echo -e "\nService Information:"
[ "$INSTALL_APT_CACHE" = true ] && echo "APT-Cacher NG: http://$LOCAL_IP:$APT_CACHE_PORT"
[ "$INSTALL_DOCKER_MIRROR" = true ] && echo "Docker Registry Mirror: http://$LOCAL_IP:$DOCKER_MIRROR_PORT"
[ "$INSTALL_PIHOLE" = true ] && echo "Pi-hole Admin Interface: http://$LOCAL_IP:$PIHOLE_WEB_PORT"
[ "$INSTALL_GIT_CACHE" = true ] && echo "Gitea Interface: http://$LOCAL_IP:$GIT_CACHE_PORT"

echo -e "\nImportant Note: Please reboot the system to ensure all changes take effect."
echo -e "Log file location: $LOG_FILE"

exit 0