#!/bin/bash
set -e

BINARY="${1:-build/domudns}"
COREDNS_BINARY="${2:-build/coredns}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/domudns}"

if [ ! -f "$BINARY" ]; then
  echo "Binary not found: $BINARY"
  echo "Build first with: make build"
  exit 1
fi

echo "Installing lightweight-domudns..."
sudo cp "$BINARY" "$INSTALL_DIR/domudns"
sudo chmod +x "$INSTALL_DIR/domudns"

if [ -f "$COREDNS_BINARY" ]; then
  echo "Installing CoreDNS..."
  sudo cp "$COREDNS_BINARY" "$INSTALL_DIR/coredns"
  sudo chmod +x "$INSTALL_DIR/coredns"
fi

echo "Installing config..."
sudo mkdir -p "$CONFIG_DIR"
if [ -f configs/config.yaml ]; then
  sudo cp configs/config.yaml "$CONFIG_DIR/"
  echo "  Config: $CONFIG_DIR/config.yaml"
else
  echo "  Warning: configs/config.yaml not found"
fi

echo "Generating Corefile..."
if sudo "$INSTALL_DIR/domudns" -config "$CONFIG_DIR/config.yaml" -generate-corefile "$CONFIG_DIR/Corefile" 2>/dev/null; then
  echo "  Corefile: $CONFIG_DIR/Corefile"
else
  echo "  Warning: could not generate Corefile. Run manually: sudo $INSTALL_DIR/domudns -config $CONFIG_DIR/config.yaml -generate-corefile $CONFIG_DIR/Corefile"
fi

echo "Installing systemd services..."
if [ -f scripts/systemd/domudns.service ]; then
  sudo cp scripts/systemd/domudns.service /etc/systemd/system/
fi
if [ -f scripts/systemd/coredns.service ]; then
  sudo cp scripts/systemd/coredns.service /etc/systemd/system/
fi
sudo systemctl daemon-reload
echo "  Services installed"

echo ""
echo "Installation complete."
echo ""
echo "Next steps:"
echo "  1. Edit config: sudo nano $CONFIG_DIR/config.yaml"
echo "  2. Set API key: openssl rand -base64 32"
echo "  3. Regenerate Corefile if needed: $INSTALL_DIR/domudns -config $CONFIG_DIR/config.yaml -generate-corefile $CONFIG_DIR/Corefile"
echo "  4. Start: sudo systemctl start coredns domudns"
echo "  5. Enable: sudo systemctl enable coredns domudns"
echo "  6. Status: sudo systemctl status coredns domudns"
