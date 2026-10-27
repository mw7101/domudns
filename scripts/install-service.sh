#!/bin/bash
set -e

# Installation von domudns systemd Service und Config
# Läuft auf Raspberry Pi

echo "🔧 Installiere domudns Service..."

# 1. Erstelle Config-Verzeichnis
echo "📁 Erstelle /etc/domudns/..."
sudo mkdir -p /etc/domudns

# 2. Kopiere Config (falls nicht vorhanden)
if [ ! -f /etc/domudns/config.yaml ]; then
    echo "📝 Kopiere Standard-Config..."
    if [ -f configs/config.yaml ]; then
        sudo cp configs/config.yaml /etc/domudns/config.yaml
    else
        echo "⚠️  configs/config.yaml nicht gefunden - bitte manuell kopieren"
        echo "   sudo cp configs/config.yaml /etc/domudns/config.yaml"
    fi
else
    echo "ℹ️  Config bereits vorhanden: /etc/domudns/config.yaml"
fi

# 3. Installiere systemd Service
echo "🔧 Installiere systemd Service..."
sudo cp scripts/domudns.service /etc/systemd/system/domudns.service
sudo chmod 644 /etc/systemd/system/domudns.service

# 4. Reload systemd
echo "🔄 Reload systemd..."
sudo systemctl daemon-reload

# 5. Enable und Start Service
echo "▶️  Enable und starte Service..."
sudo systemctl enable domudns
sudo systemctl start domudns

# 6. Status prüfen
echo ""
echo "✅ Installation abgeschlossen!"
echo ""
echo "Status:"
sudo systemctl status domudns --no-pager -l

echo ""
echo "Nützliche Befehle:"
echo "  sudo systemctl status domudns    # Status anzeigen"
echo "  sudo systemctl restart domudns   # Neustart"
echo "  sudo systemctl stop domudns      # Stoppen"
echo "  sudo journalctl -u domudns -f    # Logs anzeigen"
