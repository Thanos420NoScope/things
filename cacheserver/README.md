# Cache Servers

This project contains two scripts designed to automate the setup and configuration of cache servers and client machines for bandwidth effficiency.  
It is recommended to run those only on fresh proxmox containers. Scripts have not been tested in VMs and baremetal.

## Scripts

1. `server.sh`: Sets up a server with various tools and configurations.
2. `client.sh`: Configures a client machine with essential tools and optimizations.

## Features

Both scripts include the following features:

- System update and upgrade
- Installation of essential tools (Docker, Git, Python, etc.)
- SSH configuration (disabling password authentication)
- Fail2ban setup
- Automatic security updates
- Timezone setting (America/New_York)
- System optimization
- GitHub key addition from a specified GitHub username

### Server-specific features

- Optional installation of APT-Cacher NG
- Optional installation of Docker Registry Mirror
- Optional installation of Pi-hole

### Client-specific features

- Optional configuration of APT cache server
- Optional configuration of Docker registry mirror
- Optional configuration of Pi-hole DNS server

## Usage

### Server Setup
Quick: (Edit Username)
```bash
wget -O server.sh https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/server.sh && chmod +x server.sh && ./server.sh --install-apt-cache --install-docker-mirror --install-pihole --github-user YourGitHubUsername
```
Manual:
```bash
sudo ./server.sh [OPTIONS]
```

Options:
- `-h, --help`: Show help message and exit
- `-y`: Skip confirmation prompt
- `--install-apt-cache`: Install APT-Cacher NG
- `--install-docker-mirror`: Install Docker Registry Mirror
- `--install-pihole`: Install Pi-hole
- `--github-user USERNAME`: Specify the GitHub username for SSH key addition (required)

Example:
```bash
sudo ./server.sh --install-apt-cache --install-docker-mirror --install-pihole --github-user YourGitHubUsername
```

### Client Setup
Quick: (Edit IPs and Username)
```bash
wget -O client.sh https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/client.sh && chmod +x client.sh && ./client.sh --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55:5000 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername
```
Manual:
```bash
sudo ./client.sh [OPTIONS]
```

Options:
- `-h, --help`: Show help message and exit
- `-y`: Skip confirmation prompt
- `--apt-cache SERVER`: Use specified APT cache server
- `--docker-mirror SERVER`: Use specified Docker registry mirror
- `--pihole-dns SERVER`: Use specified Pi-hole DNS server
- `--github-user USERNAME`: Specify the GitHub username for SSH key addition (required)

Example:
```bash
sudo ./client.sh --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55:5000 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername
```

## Logging

Both scripts log their actions to `/var/log/server_setup.log` or `/var/log/client_setup.log` respectively.

## Security Considerations

- These scripts must be run as root.
- They disable SSH password authentication, so make sure you have SSH key access set up before running them.
- The scripts add GitHub keys from the specified GitHub user. Make sure to provide a valid GitHub username.

## Post installation

- Docker cache: /var/lib/docker-registry
- PiHole stats: http://192.168.2.55/admin/index.php
- APT-NG: http://192.168.2.55:3142/acng-report.html?doCount=Count+Data
