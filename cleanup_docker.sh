#!/bin/bash
# ============================================================
#  cleanup_docker.sh
#  Menghapus semua container dan network yang dibuat
# ============================================================

echo "Stopping and removing containers..."
docker stop alice bob 2>/dev/null || true
docker rm alice bob 2>/dev/null || true

echo "Removing network..."
docker network rm secure-net 2>/dev/null || true

echo "✓ Cleanup complete."
