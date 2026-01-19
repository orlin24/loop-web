#!/bin/bash
# LoopWeb VPS Setup Script untuk Ubuntu 22.04
# Jalankan dengan: sudo bash setup_vps.sh

set -e

echo "=== LoopWeb VPS Setup ==="

# Update system
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y python3 python3-pip python3-venv ffmpeg nginx cpulimit

# Create app directory
mkdir -p /opt/loopweb
mkdir -p /var/log/loopweb

# Copy application files (sesuaikan path)
# cp -r /path/to/Loop-web/* /opt/loopweb/

# Create virtual environment
cd /opt/loopweb
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Set permissions
chown -R www-data:www-data /opt/loopweb
chown -R www-data:www-data /var/log/loopweb
chmod -R 755 /opt/loopweb

# Setup systemd service
cp loopweb.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable loopweb
systemctl start loopweb

# Setup logrotate untuk log cleanup otomatis
cat > /etc/logrotate.d/loopweb << 'EOF'
/var/log/loopweb/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload loopweb > /dev/null 2>&1 || true
    endscript
}

/opt/loopweb/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
}
EOF

# Setup cron untuk cleanup temp files mingguan
(crontab -l 2>/dev/null; echo "0 3 * * 0 find /opt/loopweb/uploads -name '*.tmp' -mtime +7 -delete") | crontab -

echo "=== Setup Complete ==="
echo "Check status: systemctl status loopweb"
echo "View logs: journalctl -u loopweb -f"
