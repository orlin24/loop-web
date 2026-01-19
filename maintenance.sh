#!/bin/bash
# LoopWeb Maintenance Script
# Jalankan secara berkala: sudo bash maintenance.sh

echo "=== LoopWeb Maintenance ==="
echo "Date: $(date)"

# Cleanup temp files
echo "Cleaning temp files..."
find /opt/loopweb/uploads -name "*.tmp" -mtime +1 -delete 2>/dev/null || true
find /tmp -name "gdown*" -mtime +1 -delete 2>/dev/null || true

# Cleanup old logs
echo "Cleaning old logs..."
find /opt/loopweb/logs -name "*.log.*" -mtime +30 -delete 2>/dev/null || true

# Check for zombie processes
echo "Checking for zombie FFmpeg processes..."
zombies=$(ps aux | grep -E "ffmpeg|cpulimit" | grep -v grep | grep "Z" | wc -l)
if [ "$zombies" -gt 0 ]; then
    echo "Warning: Found $zombies zombie processes"
    # Kill parent process to clean up zombies
    ps aux | grep -E "ffmpeg|cpulimit" | grep "Z" | awk '{print $2}' | xargs -r kill -9 2>/dev/null || true
fi

# Check memory usage
mem_usage=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
echo "Memory usage: ${mem_usage}%"
if [ "$mem_usage" -gt 90 ]; then
    echo "Warning: High memory usage, restarting service..."
    systemctl restart loopweb
fi

# Check disk usage
disk_usage=$(df /opt/loopweb | tail -1 | awk '{print int($5)}')
echo "Disk usage: ${disk_usage}%"
if [ "$disk_usage" -gt 90 ]; then
    echo "Warning: High disk usage!"
    echo "Consider cleaning up old videos in /opt/loopweb/uploads/"
fi

# Service health check
if ! systemctl is-active --quiet loopweb; then
    echo "Service is down, restarting..."
    systemctl restart loopweb
else
    echo "Service is running normally"
fi

# Show resource stats
echo ""
echo "=== Resource Stats ==="
echo "Active FFmpeg processes: $(pgrep -c ffmpeg 2>/dev/null || echo 0)"
echo "Total threads: $(ps -eLf | grep -c python 2>/dev/null || echo 0)"
echo "Uptime: $(uptime -p)"

echo ""
echo "=== Maintenance Complete ==="
