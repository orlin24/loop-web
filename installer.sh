#!/bin/bash
# LoopWeb Auto Installer
# Usage: wget -O installer.sh https://raw.githubusercontent.com/orlin24/loop-web/main/installer.sh && chmod +x installer.sh && sudo ./installer.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════╗"
echo "║        LoopWeb Auto Installer            ║"
echo "║     YouTube Live Streaming Bot           ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root: sudo ./installer.sh${NC}"
    exit 1
fi

# Installation mode
echo -e "${YELLOW}Select installation mode:${NC}"
echo "1) Full Install with SSL (requires domain)"
echo "2) Basic Install (IP only, no SSL)"
read -p "Enter choice [1/2]: " INSTALL_MODE

DOMAIN=""
EMAIL=""
USE_SSL=false

if [ "$INSTALL_MODE" == "1" ]; then
    USE_SSL=true
    read -p "Enter your domain (e.g., loopbotiq.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}Domain is required for SSL installation!${NC}"
        exit 1
    fi
    read -p "Enter your email for SSL certificate: " EMAIL
    if [ -z "$EMAIL" ]; then
        echo -e "${RED}Email is required for SSL!${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Installing with SSL for domain: ${DOMAIN}${NC}"
else
    echo -e "${YELLOW}Installing basic mode (no SSL)${NC}"
fi

echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."

# ========================================
# Step 1: Update System & Install Dependencies
# ========================================
echo -e "${GREEN}[1/7] Updating system and installing dependencies...${NC}"
apt-get update
apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv ffmpeg git curl tmux

if [ "$USE_SSL" = true ]; then
    apt-get install -y nginx certbot python3-certbot-nginx
fi

# ========================================
# Step 2: Configure Firewall
# ========================================
echo -e "${GREEN}[2/7] Configuring firewall...${NC}"
ufw allow OpenSSH
ufw allow 5000/tcp
ufw allow 1935/tcp
ufw allow 80/tcp
ufw allow 443/tcp
echo "y" | ufw enable

# ========================================
# Step 3: Clone Repository
# ========================================
echo -e "${GREEN}[3/7] Cloning LoopWeb repository...${NC}"
mkdir -p /var/www/html
cd /var/www/html

if [ -d "loop-web" ]; then
    echo -e "${YELLOW}Existing installation found. Updating...${NC}"
    cd loop-web
    git pull
    cd ..
else
    git clone https://github.com/orlin24/loop-web.git
fi

cd loop-web

# Create required directories
mkdir -p uploads
mkdir -p LoopBot/thumbnails
mkdir -p LoopBot/content
mkdir -p logs

# ========================================
# Step 4: Setup Python Environment
# ========================================
echo -e "${GREEN}[4/7] Setting up Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

# ========================================
# Step 5: Set Permissions
# ========================================
echo -e "${GREEN}[5/7] Setting permissions...${NC}"
timedatectl set-timezone Asia/Jakarta

# Create .cache directory for gdown (Google Drive downloads)
mkdir -p /var/www/.cache
chown -R www-data:www-data /var/www/.cache

chown -R www-data:www-data /var/www/html/loop-web
chmod -R 755 /var/www/html/loop-web
chmod 700 /var/www/html/loop-web/LoopBot

# ========================================
# Step 6: Setup Nginx & SSL (if enabled)
# ========================================
if [ "$USE_SSL" = true ]; then
    echo -e "${GREEN}[6/7] Configuring Nginx and SSL...${NC}"

    cat > /etc/nginx/sites-available/loopweb << EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
    }

    client_max_body_size 500M;
}
EOF

    ln -sf /etc/nginx/sites-available/loopweb /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx

    # Get SSL certificate
    certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --email ${EMAIL} --redirect

    # Setup auto-renewal
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
else
    echo -e "${GREEN}[6/7] Skipping Nginx/SSL (basic mode)...${NC}"
fi

# ========================================
# Step 7: Setup Systemd Service
# ========================================
echo -e "${GREEN}[7/7] Setting up systemd service...${NC}"

cat > /etc/systemd/system/loopweb.service << 'EOF'
[Unit]
Description=LoopWeb YouTube Streaming Bot
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html/loop-web
Environment="PATH=/var/www/html/loop-web/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="HOME=/var/www"
ExecStart=/var/www/html/loop-web/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Setup logrotate
cat > /etc/logrotate.d/loopweb << 'EOF'
/var/www/html/loop-web/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
}
EOF

# Setup maintenance cron
cat > /etc/cron.d/loopweb-maintenance << 'EOF'
0 3 * * * root find /var/www/html/loop-web/uploads -name "*.tmp" -mtime +1 -delete 2>/dev/null
0 4 * * 0 root find /var/www/html/loop-web/logs -name "*.log.*" -mtime +30 -delete 2>/dev/null
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable loopweb
systemctl start loopweb

if [ "$USE_SSL" = true ]; then
    systemctl restart nginx
fi

# Get IP
IP=$(hostname -I | awk '{print $1}')

# ========================================
# Done!
# ========================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Installation Complete!              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""

if [ "$USE_SSL" = true ]; then
    echo -e "${BLUE}Your LoopWeb is now running at:${NC}"
    echo -e "${YELLOW}  https://${DOMAIN}${NC}"
else
    echo -e "${BLUE}Your LoopWeb is now running at:${NC}"
    echo -e "${YELLOW}  http://${IP}:5000${NC}"
fi

echo ""
echo -e "${BLUE}Default Login:${NC}"
echo -e "  Username: ${YELLOW}admin${NC}"
echo -e "  Password: ${YELLOW}admin${NC}"
echo ""
echo -e "${RED}IMPORTANT: Change your password after first login!${NC}"
echo ""
echo -e "${BLUE}Useful Commands:${NC}"
echo -e "  Check status:  ${YELLOW}systemctl status loopweb${NC}"
echo -e "  View logs:     ${YELLOW}journalctl -u loopweb -f${NC}"
echo -e "  Restart:       ${YELLOW}systemctl restart loopweb${NC}"
echo -e "  Stop:          ${YELLOW}systemctl stop loopweb${NC}"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Login with admin/admin"
echo "  2. Change password in Settings"
echo "  3. Upload client_secrets.json from Google Cloud Console"
echo "  4. Connect your YouTube channel"
echo ""

# Cleanup installer
rm -f "$(realpath "$0")"
