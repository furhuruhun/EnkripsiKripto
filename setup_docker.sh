#!/bin/bash
# ============================================================
#  setup_docker.sh
#  Otomasi setup Docker untuk End-to-End Secure Messaging
#  
#  Script ini akan:
#   1. Membuat Docker network dengan subnet 192.168.1.0/24
#   2. Membuat container Alice (192.168.1.10) dan Bob (192.168.1.20)
#   3. Install dependencies di kedua container
#   4. Copy source code ke kedua container
#   5. Generate RSA keys dan distribusikan
#   6. Verifikasi konektivitas
# ============================================================

set -e

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

NETWORK_NAME="secure-net"
SUBNET="192.168.5.0/24"
ALICE_IP="192.168.5.10"
BOB_IP="192.168.5.20"
ALICE_PORT=5000
BOB_PORT=5001
IMAGE="python:3.11-slim"

echo ""
echo -e "${CYAN}========================================================${NC}"
echo -e "${CYAN}  End-to-End Secure Messaging — Docker Setup${NC}"
echo -e "${CYAN}========================================================${NC}"
echo ""

# -----------------------------------------------------------
# Step 1: Cleanup previous setup (if any)
# -----------------------------------------------------------
echo -e "${YELLOW}[1/7] Cleaning up previous containers...${NC}"
docker stop alice bob 2>/dev/null || true
docker rm alice bob 2>/dev/null || true
docker network rm $NETWORK_NAME 2>/dev/null || true
echo -e "${GREEN}  ✓ Cleanup done.${NC}"

# -----------------------------------------------------------
# Step 2: Create Docker network
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[2/7] Creating Docker network: $NETWORK_NAME ($SUBNET)...${NC}"
docker network create --subnet=$SUBNET $NETWORK_NAME
echo -e "${GREEN}  ✓ Network created.${NC}"

# -----------------------------------------------------------
# Step 3: Start containers
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[3/7] Starting containers...${NC}"
docker run -dit --name alice \
    --network $NETWORK_NAME \
    --ip $ALICE_IP \
    $IMAGE

docker run -dit --name bob \
    --network $NETWORK_NAME \
    --ip $BOB_IP \
    $IMAGE

echo -e "${GREEN}  ✓ Alice ($ALICE_IP) running.${NC}"
echo -e "${GREEN}  ✓ Bob   ($BOB_IP) running.${NC}"

# -----------------------------------------------------------
# Step 4: Install dependencies
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[4/7] Installing Python cryptography library...${NC}"
docker exec alice pip install cryptography --quiet 2>&1 | tail -1
docker exec bob pip install cryptography --quiet 2>&1 | tail -1
echo -e "${GREEN}  ✓ Dependencies installed on both containers.${NC}"

# -----------------------------------------------------------
# Step 5: Copy source code
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[5/7] Copying source code to containers...${NC}"

# Pastikan directory /app ada
docker exec alice mkdir -p /app/keys
docker exec bob mkdir -p /app/keys

# Copy scripts
docker cp generate_keys.py alice:/app/generate_keys.py
docker cp secure_node.py alice:/app/secure_node.py
docker cp generate_keys.py bob:/app/generate_keys.py
docker cp secure_node.py bob:/app/secure_node.py

echo -e "${GREEN}  ✓ Source code copied.${NC}"

# -----------------------------------------------------------
# Step 6: Generate & distribute keys
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[6/7] Generating RSA key pairs and distributing...${NC}"

# Generate keys inside Alice's container
docker exec alice python /app/generate_keys.py /app/keys

# Copy keys from Alice to host temporarily, then to Bob
docker cp alice:/app/keys/. /tmp/secure_msg_keys/
docker cp /tmp/secure_msg_keys/. bob:/app/keys/

# Cleanup temp files
rm -rf /tmp/secure_msg_keys

echo -e "${GREEN}  ✓ Keys generated and distributed to both containers.${NC}"
echo ""
echo "  Key distribution:"
echo "    Alice has: alice_private.pem, alice_public.pem, bob_public.pem"
echo "    Bob   has: bob_private.pem, bob_public.pem, alice_public.pem"

# -----------------------------------------------------------
# Step 7: Verify connectivity
# -----------------------------------------------------------
echo ""
echo -e "${YELLOW}[7/7] Verifying connectivity...${NC}"

echo "  Ping Alice → Bob:"
docker exec alice ping -c 2 -W 1 $BOB_IP 2>&1 | grep -E "bytes from|packet loss" | sed 's/^/    /'

echo "  Ping Bob → Alice:"
docker exec bob ping -c 2 -W 1 $ALICE_IP 2>&1 | grep -E "bytes from|packet loss" | sed 's/^/    /'

echo -e "${GREEN}  ✓ Connectivity verified.${NC}"

# -----------------------------------------------------------
# Done!
# -----------------------------------------------------------
echo ""
echo -e "${CYAN}========================================================${NC}"
echo -e "${CYAN}  ✓ SETUP COMPLETE!${NC}"
echo -e "${CYAN}========================================================${NC}"
echo ""
echo -e "  ${GREEN}Alice${NC}: $ALICE_IP (container: alice)"
echo -e "  ${GREEN}Bob${NC}  : $BOB_IP   (container: bob)"
echo ""
echo "  Sekarang buka 2 terminal dan jalankan:"
echo ""
echo -e "  ${CYAN}Terminal 1 — Bob (listener pertama):${NC}"
echo "  docker exec -it bob python /app/secure_node.py \\"
echo "      --name bob \\"
echo "      --listen-port $BOB_PORT \\"
echo "      --my-private-key /app/keys/bob_private.pem \\"
echo "      --my-public-key /app/keys/bob_public.pem \\"
echo "      --peer-public-key /app/keys/alice_public.pem \\"
echo "      --peer-host $ALICE_IP --peer-port $ALICE_PORT \\"
echo "      --my-ip $BOB_IP"
echo ""
echo -e "  ${CYAN}Terminal 2 — Alice (sender):${NC}"
echo "  docker exec -it alice python /app/secure_node.py \\"
echo "      --name alice \\"
echo "      --listen-port $ALICE_PORT \\"
echo "      --my-private-key /app/keys/alice_private.pem \\"
echo "      --my-public-key /app/keys/alice_public.pem \\"
echo "      --peer-public-key /app/keys/bob_public.pem \\"
echo "      --peer-host $BOB_IP --peer-port $BOB_PORT \\"
echo "      --my-ip $ALICE_IP"
echo ""
echo "  Ketik pesan di salah satu terminal, tekan Enter untuk kirim."
echo "  Kedua arah bisa saling kirim pesan!"
echo ""
