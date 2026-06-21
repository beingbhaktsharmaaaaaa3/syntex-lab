# Setup Guide — Syntex Lab

## Prerequisites
- Docker Desktop or Docker Engine + Docker Compose
- 2GB free RAM, 1GB disk
- Kali Linux, Ubuntu, macOS, or Windows with WSL2

## Install Docker (Kali Linux)
```bash
sudo apt update
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
newgrp docker
```

## Start the Lab
```bash
git clone https://github.com/YOUR_USERNAME/syntex-lab.git
cd syntex-lab

# Docker Compose v1 (older systems, Kali default):
docker-compose up --build

# Docker Compose v2 (newer systems):
docker compose up --build
```

## /etc/hosts setup
```bash
sudo bash -c 'cat >> /etc/hosts << "HOSTS"
127.0.0.1 syntex.local www.syntex.local api.syntex.local admin.syntex.local
127.0.0.1 dev.syntex.local staging.syntex.local cdn.syntex.local program.syntex.local
127.0.0.1 mail.syntex.local backup.syntex.local vpn.syntex.local intranet.syntex.local
127.0.0.1 git.syntex.local jenkins.syntex.local jira.syntex.local prometheus.syntex.local
HOSTS'
```

## Verify it works
```bash
curl -I http://localhost:3000/health
curl -I http://syntex.local         # Needs /etc/hosts
```
