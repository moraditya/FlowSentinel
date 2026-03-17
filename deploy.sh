#!/bin/bash
# NIDS Platform - EC2 Deployment Script
# Run this ON the EC2 instance after cloning the repo

set -e

echo "=== NIDS Platform Deployment ==="

# Get the public IP via IMDSv2 first, then fall back to manual entry.
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true)

if [ -n "$TOKEN" ]; then
  EC2_PUBLIC_IP=$(curl -sS \
    -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/public-ipv4" || true)
fi

if [ -z "$EC2_PUBLIC_IP" ]; then
  echo "Could not auto-detect public IP. Enter it manually:"
  read -r EC2_PUBLIC_IP
fi
echo "Public IP: $EC2_PUBLIC_IP"

# Generate a random API key if not set.
if [ -z "$NIDS_API_KEY" ]; then
  NIDS_API_KEY=$(openssl rand -hex 16)
  echo "Generated API key: $NIDS_API_KEY"
  echo "Save this - you'll need it to start capture on the dashboard."
fi

# Default CORS to the dashboard origin.
CORS_ORIGINS="${CORS_ORIGINS:-http://$EC2_PUBLIC_IP:3000}"

# Write production env file.
cat > .env.prod <<EOF
NIDS_MODE=production
EC2_PUBLIC_IP=$EC2_PUBLIC_IP
NIDS_API_KEY=$NIDS_API_KEY
CORS_ORIGINS=$CORS_ORIGINS
NIDS_CAPTURE_INTERFACE=${NIDS_CAPTURE_INTERFACE:-eth0}
EOF

echo "=== Building and starting containers ==="
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build

echo ""
echo "=== Deployment complete ==="
echo "Dashboard:  http://$EC2_PUBLIC_IP:3000"
echo "API:        http://$EC2_PUBLIC_IP:8000"
echo "API Docs:   http://$EC2_PUBLIC_IP:8000/docs"
echo "API Key:    $NIDS_API_KEY"
echo "Mode:       production"
echo ""
echo "Check status: docker compose -f docker-compose.prod.yml logs -f"
