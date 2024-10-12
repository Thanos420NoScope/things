# Cache Server

This project contains two scripts designed to automate the setup and configuration of cache servers and client machines for bandwidth effficiency.  
It is recommended to run those only on fresh proxmox containers. Scripts have not been tested in VMs and baremetal.

## Scripts

1. `server.sh`: Configures a server with hardened configuration and various caching tools.
2. `client.sh`: Configures a client with hardened configuration using the cache server.

## Features

Both scripts include the following features:

- System update and upgrade
- Installation of essential tools (Docker, Git, Python, etc.)
- SSH configuration (disabling password authentication)
- GitHub key addition from a specified GitHub username
- Fail2ban setup
- Automatic security updates
- Timezone setting (America/New_York)
- System optimization


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
./server.sh [OPTIONS]
```

Options:
- `-h, --help`: Show help message and exit
- `-y`: Skip confirmation prompt
- `--install-apt-cache`: Install APT-Cacher NG
- `--install-docker-mirror`: Install Docker Registry Mirror
- `--install-pihole`: Install Pi-hole
- `--github-user USERNAME`: Specify the GitHub username for SSH key addition (required)

Examples:
```bash
./server.sh --install-pihole --github-user YourGitHubUsername
```
```bash
./server.sh --install-apt-cache --install-docker-mirror --install-pihole --github-user YourGitHubUsername
```

### Client Setup
Quick: (Edit IPs and Username)
```bash
wget -O client.sh https://raw.githubusercontent.com/Thanos420NoScope/things/refs/heads/main/cacheserver/client.sh && chmod +x client.sh && ./client.sh --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55:5000 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername
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

Examples:
```bash
./client.sh --pihole-dns 192.168.2.31 --docker-mirror 192.168.2.55:5000 --github-user YourGitHubUsername
```
```bash
./client.sh --apt-cache 192.168.2.55 --docker-mirror 192.168.2.55:5000 --pihole-dns 192.168.2.55 --github-user YourGitHubUsername
```

## Logging

Both scripts log their actions to `/var/log/server_setup.log` or `/var/log/client_setup.log` respectively.

## Security Considerations

- These scripts must be run as root.
- The scripts disable password authentication and add ssh keys from the specified GitHub user, make sure to provide a GitHub username with valid authentication keys.
- If this server dies, clients lose connectivity. Consider running this in HA if you have multiple servers.

## Post installation

- Docker cache: /var/lib/docker-registry
- PiHole stats: http://192.168.2.55/admin/index.php
- APT-NG stats: http://192.168.2.55:3142/acng-report.html?doCount=Count+Data
