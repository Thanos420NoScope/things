# Cache Server

This project contains scripts designed to automate the setup and configuration of cache servers and client machines for bandwidth efficiency and enhanced security.  
It is recommended to run these only on fresh proxmox containers. Scripts have not been tested in VMs and baremetal.

## Scripts

1. `server.sh`: Configures a server with hardened configuration, UFW firewall, and various caching tools.
2. `client.sh`: Configures a client with hardened configuration and UFW firewall using the cache server.
3. `release.py`: Syncs GitHub releases to Gitea for mirrored repositories (automatically installed by server.sh).

## Features

Both server and client scripts include the following features:

- System update and upgrade
- Installation of essential tools (Docker, Git, Python, etc.)
- SSH configuration (disabling password authentication)
- UFW firewall configuration with secure defaults
- GitHub key addition from a specified GitHub username
- Fail2ban setup (integrated with UFW)
- Automatic security updates
- Configurable timezone setting (default: America/New_York)
- System optimization

### Server-specific features

- Optional installation of APT-Cacher NG (Port 8000)
- Optional installation of Docker Registry Mirror (Port 8001)
- Optional installation of Pi-hole (Port 8002, DNS 53)
- Optional installation of Gitea (Port 8003)
- Automatic GitHub release synchronization for mirrored repositories
- UFW configured to allow required service ports
- Integration with fail2ban for enhanced security

### Client-specific features

- Optional configuration of APT cache server
- Optional configuration of Docker registry mirror
- Optional configuration of Pi-hole DNS server
- UFW configured for secure outbound access to services
- Default deny incoming, allow outgoing policy

## Usage

### Server Setup
Quick: (Edit Username and add GitHub token)
```bash
wget -O server.sh https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/server.sh && chmod +x server.sh && ./server.sh --install-apt-cache --install-docker-mirror --install-pihole --install-git-cache --github-user YourGitHubUsername --github-token YourGitHubToken
```
Manual:
```bash
./server.sh [OPTIONS]
```

Options:
- `-h, --help`: Show help message and exit
- `-y`: Skip confirmation prompt
- `--install-apt-cache`: Install APT-Cacher NG
- `--install-docker-mirror`: Install Docker Registry Mirror
- `--install-pihole`: Install Pi-hole
- `--install-git-cache`: Install Gitea (Git server)
- `--github-user USERNAME`: Specify the GitHub username for SSH key addition (required)
- `--github-token TOKEN`: Specify the GitHub token for release synchronization (required)
- `--timezone TIMEZONE`: Set the timezone (default: America/New_York)

Examples:
```bash
./server.sh --install-pihole --github-user YourGitHubUsername --github-token YourGitHubToken
```
```bash
./server.sh --install-apt-cache --install-docker-mirror --install-pihole --install-git-cache --github-user YourGitHubUsername --github-token YourGitHubToken --timezone Europe/London
```

### Client Setup
Quick: (Edit IPs and Username)
```bash
wget -O client.sh https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/client.sh && chmod +x client.sh && ./client.sh --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername
```
Manual:
```bash
./client.sh [OPTIONS]
```

Options:
- `-h, --help`: Show help message and exit
- `-y`: Skip confirmation prompt
- `--apt-cache SERVER`: Use specified APT cache server
- `--docker-mirror SERVER`: Use specified Docker registry mirror
- `--pihole-dns SERVER`: Use specified Pi-hole DNS server
- `--github-user USERNAME`: Specify the GitHub username for SSH key addition (required)
- `--timezone TIMEZONE`: Set the timezone (default: America/New_York)

## Port Configuration

### Server Ports
- SSH: 22/tcp
- APT-Cacher NG: 8000/tcp
- Docker Registry Mirror: 8001/tcp
- Pi-hole Web Interface: 8002/tcp
- Pi-hole DNS: 53/tcp, 53/udp
- Gitea: 8003/tcp

### Client Firewall
- Allows SSH (22/tcp) in/out
- Allows outbound access to configured services
- Denies all incoming by default
- Allows all outbound by default
- Allows established connections

## Logging

Both scripts log their actions:
- Server script: `/var/log/server_setup.log`
- Client script: `/var/log/client_setup.log`

## Security Considerations

- The scripts must be run as root
- UFW is configured with secure defaults (deny incoming, allow outgoing)
- SSH password authentication is disabled
- fail2ban is integrated with UFW for additional protection
- GitHub SSH keys are required for authentication
- GitHub token is required for release synchronization
- If the server dies, clients lose connectivity. Consider running it in HA if you have multiple servers

## Post installation

- Docker cache: /var/lib/docker-registry
- PiHole admin interface: http://SERVER_IP:8002/admin
- APT-Cacher NG statistics: http://SERVER_IP:8000/acng-report.html
- Gitea web interface: http://SERVER_IP:8003

### Using Gitea

After installation:
1. Access the Gitea web interface at http://SERVER_IP:8003
2. Log in with default credentials:
   - Username: root
   - Password: password
3. To mirror a repository:
   - Click the "+" button at the top right
   - Select "New Migration"
   - Choose "GitHub"
   - Enter the repository URL
   - Configure mirroring options as needed

### Release Synchronization

The `release.py` script is automatically installed and configured by the server setup script. It:
- Runs every 30 minutes via cron
- Synchronizes releases from GitHub to Gitea for all mirrored repositories
- Uses the provided GitHub token for authentication
- Logs all activities to the sync log file
- Handles rate limiting and retries automatically
- Maintains release metadata including descriptions, tags, and prerelease status