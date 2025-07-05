#!/usr/bin/env bash
# ------------------------------------------------------------
#  startup script for Phicoin DNS seed
#  This script builds the dnsseed binary (if necessary) and
#  launches it so that it answers as host "seed1.phicoin.net".
#  Adjust variables below to fit your environment.
# ------------------------------------------------------------

set -euo pipefail

# -------- configuration -------------------------------------------------------
SEED_HOST="seed1.phicoin.net"     # Hostname of the DNS seed (-h)
NS_HOST="ns1.phicoin.net"        # Authoritative nameserver hostname (-n)
ADMIN_MAIL="dns@phicoin.net"      # E-mail used in SOA records (-m)
DNS_PORT=53                        # UDP port to listen on (-p)
CRAWLER_THREADS=96                 # Number of crawler threads (-t)
DNS_THREADS=4                      # Number of DNS worker threads (-d)
# -----------------------------------------------------------------------------

# Determine script directory and switch to project root (assuming script lives there)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# -------- build step ----------------------------------------------------------
if [[ ! -f dnsseed ]]; then
  echo "[INFO] Building dnsseed binary…"
  make
fi

# Allow binding to port 53 without root (Linux only). Ignore errors if setcap is
# unavailable or we lack privileges.
if command -v setcap &>/dev/null; then
  sudo setcap cap_net_bind_service=+ep ./dnsseed || true
fi

# -------- launch --------------------------------------------------------------
echo "[INFO] Starting dnsseed for host $SEED_HOST (NS: $NS_HOST) on port $DNS_PORT…"
exec ./dnsseed \
  -h "$SEED_HOST" \
  -n "$NS_HOST" \
  -m "$ADMIN_MAIL" \
  -t "$CRAWLER_THREADS" \
  -d "$DNS_THREADS" \
  -p "$DNS_PORT" 