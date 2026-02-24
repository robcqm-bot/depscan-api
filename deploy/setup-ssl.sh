#!/bin/bash
# Run once on the server to obtain Let's Encrypt certificate for depscan.net
# Requires: certbot installed, DNS pointing to this server, port 80 open

set -e

DOMAIN="depscan.net"

echo "=== Obtaining SSL certificate for  ==="

# Stop nginx temporarily (standalone mode)
systemctl stop nginx || true

certbot certonly   --standalone   --non-interactive   --agree-tos   --email admin@depscan.net   -d ""   -d "www."

# Restart nginx
systemctl start nginx

echo ""
echo "Certificate obtained!"
echo "Now install the nginx config:"
echo "  cp /opt/depscan-api/deploy/nginx-depscan.conf /etc/nginx/sites-available/depscan.net"
echo "  ln -s /etc/nginx/sites-available/depscan.net /etc/nginx/sites-enabled/"
echo "  nginx -t && systemctl reload nginx"
