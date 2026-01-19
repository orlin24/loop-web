#!/bin/bash
set -e

# Pastikan script dijalankan sebagai root (atau bisa sudo)
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)" 
   exit 1
fi

# Ask for domain
read -p "Masukkan nama domain Anda (tanpa https://), contoh: loopbotiq.com: " DOMAIN_NAME

if [ -z "$DOMAIN_NAME" ]; then
    echo "Nama domain tidak boleh kosong."
    exit 1
fi

echo -e "\e[32mInstalling Nginx and Certbot...\e[0m"
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx

echo -e "\e[32mConfiguring Firewall for Web Access...\e[0m"
sudo ufw allow 'Nginx Full'
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload

echo -e "\e[32mConfiguring Nginx for $DOMAIN_NAME...\e[0m"

# Create Nginx config
cat <<EOF | sudo tee /etc/nginx/sites-available/$DOMAIN_NAME
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Websocket & Long polling support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Increase timeout for long requests (streaming uploads etc)
        proxy_read_timeout 300s;
        client_max_body_size 500M;
    }
}
EOF

# Enable site
echo -e "\e[32mEnabling site configuration...\e[0m"
sudo ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test config
echo -e "\e[32mTesting Nginx configuration...\e[0m"
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

echo -e "\e[32mObtaining SSL Certificate via Let's Encrypt...\e[0m"
# Menggunakan --redirect untuk memaksa HTTPS
sudo certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME --non-interactive --agree-tos --register-unsafely-without-email --redirect

echo -e "\e[32m=============================================\e[0m"
echo -e "\e[32mInstallation Complete!\e[0m"
echo -e "\e[32mAccess your app at: https://$DOMAIN_NAME\e[0m"
echo -e "\e[33m\n[IMPORTANT STEP]\e[0m"
echo -e "Update 'Authorized redirect URIs' di Google Cloud Console menjadi:"
echo -e "\e[1;36mhttps://$DOMAIN_NAME/loopbot/oauth2callback\e[0m"
echo -e "\e[32m=============================================\e[0m"
