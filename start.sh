#!/bin/bash
# start.sh — Launch both Flask backend and Next.js frontend from one terminal.
# Press Ctrl+C to stop both servers.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"

# --- 0. Kill anything already on ports 5000 and 3000 ---
echo "▶ Checking for stale processes..."
lsof -ti:5000 2>/dev/null | xargs kill -9 2>/dev/null && echo "  Killed stale process on port 5000" || echo "  Port 5000 is free"
lsof -ti:3000 2>/dev/null | xargs kill -9 2>/dev/null && echo "  Killed stale process on port 3000" || echo "  Port 3000 is free"
sleep 1

# --- 1. Start Flask backend ---
echo "▶ Starting Flask backend..."
cd "$BACKEND_DIR"

if [ ! -d "venv" ]; then
  echo "  Creating virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt 2>/dev/null

# Start Flask in background, redirect output to log
python app.py > /tmp/ioc_flask.log 2>&1 &
FLASK_PID=$!
echo "  Flask starting (PID $FLASK_PID)..."

# Wait for Flask to be ready
echo -n "  Waiting for Flask"
for i in $(seq 1 20); do
  if curl -s http://127.0.0.1:5000/api/time > /dev/null 2>&1; then
    echo " ✓ ready"
    break
  fi
  echo -n "."
  sleep 1
  if [ $i -eq 20 ]; then
    echo " ✗ FAILED"
    echo "  Flask log:"
    cat /tmp/ioc_flask.log
    exit 1
  fi
done

# --- 2. Start Next.js frontend ---
echo ""
echo "▶ Starting Next.js frontend..."
cd "$FRONTEND_DIR"

if [ ! -d "node_modules" ]; then
  echo "  Installing npm dependencies (first run only, this takes ~1 min)..."
  npm install 2>&1 | tail -5
  if [ ! -d "node_modules" ]; then
    echo "  ✗ npm install failed"
    echo "  Try manually: cd frontend && rm -f package-lock.json && npm install"
    exit 1
  fi
fi

# Trap Ctrl+C to kill both processes
trap "echo ''; echo 'Shutting down Flask and Next.js...'; kill $FLASK_PID 2>/dev/null; exit 0" INT TERM

echo ""
echo "════════════════════════════════════════════"
echo "  IOC Enrichment Console is live!"
echo "  Open: http://localhost:3000"
echo "  Press Ctrl+C to stop both servers"
echo "════════════════════════════════════════════"
echo ""

npm run dev
