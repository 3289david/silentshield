#!/bin/bash
# SilentShield VPS deployment script
# Run once on a fresh Ubuntu 22.04 VPS as root
set -e

echo "🛡️  SilentShield VPS Setup"
echo "=========================="

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs git

# Install PM2
npm install -g pm2

# Clone repo
mkdir -p /opt/silentshield
cd /opt/silentshield
git clone https://github.com/YOUR_USERNAME/silentshield . 2>/dev/null || git pull

# Build SDK
cd sdk && npm install && node build.js
cp dist/silentshield.min.js ../public/sdk.js
cd ..

# Install server deps
cd server && npm install --production
cd ..

# Create .env
if [ ! -f server/.env ]; then
  cat > server/.env <<EOF
PORT=3000
NODE_ENV=production
DB_PATH=/opt/silentshield/data/silentshield.db
ADMIN_SECRET=$(openssl rand -hex 32)
CORS_ORIGINS=*
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=200
EOF
  mkdir -p /opt/silentshield/data
  echo "✅ .env created — check /opt/silentshield/server/.env for ADMIN_SECRET"
fi

# Start with PM2
cd server
pm2 delete silentshield 2>/dev/null || true
pm2 start index.js --name silentshield --env production
pm2 save
pm2 startup

echo ""
echo "✅ SilentShield is running!"
echo "   URL: http://$(curl -s ifconfig.me):3000"
echo ""
echo "Next steps:"
echo "  1. Point your domain to this server"
echo "  2. Install nginx: apt install nginx"
echo "  3. Set up SSL: certbot --nginx -d yourdomain.com"
echo "  4. Configure nginx to proxy port 3000"
