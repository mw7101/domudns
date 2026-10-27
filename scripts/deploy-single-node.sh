#!/bin/sh
set -e

# Deployment-Skript für einzelnen Raspberry Pi Node
# Wird von GitLab CI/CD aufgerufen
# Storage-Backend: file (JSON-Dateien, kein PostgreSQL)

# Konfiguration
PI_USER="${PI_USER:-pi}"
PI_HOST="${PI_HOST:?PI_HOST muss gesetzt sein}"
BINARY_NAME="${BINARY_NAME:-domudns}"
DEPLOY_PATH="${DEPLOY_PATH:-/usr/local/bin/domudns}"
SERVICE_NAME="${SERVICE_NAME:-domudns}"

echo "Deployment auf Node: $PI_HOST"
echo "================================================"

# 1. Binary, Service und Config zum Pi kopieren
echo "Kopiere Binary und Service-Datei..."
scp -o StrictHostKeyChecking=no \
    build/${BINARY_NAME}-arm \
    ${PI_USER}@${PI_HOST}:/tmp/${BINARY_NAME}

scp -o StrictHostKeyChecking=no \
    scripts/domudns.service \
    ${PI_USER}@${PI_HOST}:/tmp/domudns.service

# Config bei jedem Deployment übertragen
if [ -f configs/config.yaml ]; then
    echo "Übertrage config.yaml..."
    scp -o StrictHostKeyChecking=no \
        configs/config.yaml \
        ${PI_USER}@${PI_HOST}:/tmp/config.yaml
fi

# Cluster-Rolle validieren: mindestens CLUSTER_ROLE muss gesetzt sein
if [ -z "${CLUSTER_ROLE}" ]; then
    echo "FEHLER: CLUSTER_ROLE ist nicht gesetzt (master oder slave)!"
    echo "  Bitte in der GitLab CI/CD Job-Definition setzen."
    exit 1
fi
if [ "${CLUSTER_ROLE}" != "master" ] && [ "${CLUSTER_ROLE}" != "slave" ]; then
    echo "FEHLER: CLUSTER_ROLE muss 'master' oder 'slave' sein, nicht '${CLUSTER_ROLE}'"
    exit 1
fi
if [ "${CLUSTER_ROLE}" = "slave" ] && [ -z "${CLUSTER_MASTER_URL}" ]; then
    echo "FEHLER: CLUSTER_MASTER_URL muss für Slaves gesetzt sein!"
    exit 1
fi
if [ "${CLUSTER_ROLE}" = "master" ] && [ -z "${CLUSTER_SLAVES}" ]; then
    echo "Hinweis: CLUSTER_SLAVES nicht gesetzt — Node läuft als Standalone-Master (kein Cluster-Push)"
fi

echo "Cluster-Rolle: ${CLUSTER_ROLE}"

# Env-Datei bauen — Cluster-Rolle + Secrets
echo "Übertrage Env-Datei..."
{
    echo "# DNS Stack Umgebungsvariablen - automatisch gesetzt via GitLab CI/CD"
    echo "# Nicht manuell bearbeiten, wird bei jedem Deployment überschrieben"
    echo ""
    echo "# Cluster-Konfiguration (überschreibt config.yaml)"
    echo "DOMUDNS_CLUSTER_ROLE=\"${CLUSTER_ROLE}\""
    if [ -n "${CLUSTER_MASTER_URL}" ]; then
        echo "DOMUDNS_CLUSTER_MASTER_URL=\"${CLUSTER_MASTER_URL}\""
    fi
    if [ -n "${CLUSTER_SLAVES}" ]; then
        echo "DOMUDNS_CLUSTER_SLAVES=\"${CLUSTER_SLAVES}\""
    fi
    if [ -n "${DOMUDNS_SYNC_SECRET}" ]; then
        echo "DOMUDNS_SYNC_SECRET=\"${DOMUDNS_SYNC_SECRET}\""
    fi
} > /tmp/domudns-ci.env
scp -o StrictHostKeyChecking=no \
    /tmp/domudns-ci.env \
    ${PI_USER}@${PI_HOST}:/tmp/domudns.env
rm -f /tmp/domudns-ci.env

# 2. Auf dem Pi: Backup erstellen, Binary installieren, Service neustarten
echo "Installiere Binary und restarte Service..."
set +e  # Erlaube SSH-Block zu beenden mit beliebigem Exit-Code
ssh -o StrictHostKeyChecking=no ${PI_USER}@${PI_HOST} << 'EOF'
set -e

BINARY_NAME="${BINARY_NAME:-domudns}"
DEPLOY_PATH="${DEPLOY_PATH:-/usr/local/bin/domudns}"
SERVICE_NAME="${SERVICE_NAME:-domudns}"

# Migration: alten dns-stack Service stoppen (Rename dns-stack → domudns)
if sudo systemctl is-active --quiet dns-stack 2>/dev/null || sudo systemctl is-enabled --quiet dns-stack 2>/dev/null; then
  echo "Stoppe alten dns-stack Service (Migration)..."
  sudo systemctl stop dns-stack 2>/dev/null || true
  sudo systemctl disable dns-stack 2>/dev/null || true
fi

# Service stoppen
echo "Stoppe Service..."
sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true

# Sicherstellen dass Port 53 frei ist (max. 10s warten)
for i in $(seq 1 10); do
  if ! ss -ulnp 2>/dev/null | grep -q ':53 ' && ! ss -tlnp 2>/dev/null | grep -q ':53 '; then
    break
  fi
  echo "Warte auf Freigabe von Port 53 ($i/10)..."
  sleep 1
done

# Backup des alten Binary erstellen
if [ -f "${DEPLOY_PATH}" ]; then
  echo "Erstelle Backup..."
  sudo cp ${DEPLOY_PATH} ${DEPLOY_PATH}.backup
fi

# Neues Binary installieren — via mv statt cp um ETXTBSY zu vermeiden.
# cp schlägt fehl wenn der Kernel die alte Binary noch offen hält (auch nach stop).
# mv (rename syscall) ersetzt den Verzeichniseintrag atomar ohne die Inode anzufassen.
echo "Installiere neues Binary..."
sudo chmod +x /tmp/${BINARY_NAME}
sudo mv /tmp/${BINARY_NAME} ${DEPLOY_PATH}

# Capabilities setzen (für Port 53 ohne root)
echo "Setze Capabilities..."
sudo setcap 'cap_net_bind_service=+ep' ${DEPLOY_PATH} 2>/dev/null || echo "Capabilities nicht unterstützt (Service läuft als root)"

# Migration: alte Pfade (dns-stack → domudns) einmalig kopieren falls nötig
if [ -d /etc/dns-stack ] && [ ! -d /etc/domudns ]; then
  echo "Migriere /etc/dns-stack → /etc/domudns ..."
  sudo cp -r /etc/dns-stack /etc/domudns
  # Env-Vars in der kopierten env-Datei umbenennen
  sudo sed -i 's/DNS_STACK_/DOMUDNS_/g' /etc/domudns/env 2>/dev/null || true
fi
if [ -d /var/lib/dns-stack ] && [ ! -d /var/lib/domudns ]; then
  echo "Migriere /var/lib/dns-stack → /var/lib/domudns ..."
  sudo cp -r /var/lib/dns-stack /var/lib/domudns
fi

# Config-Verzeichnis und Data-Verzeichnis sicherstellen
sudo mkdir -p /etc/domudns
sudo mkdir -p /var/lib/domudns/data
sudo chmod 750 /var/lib/domudns/data

# Env-Datei aktualisieren
if [ -f /tmp/domudns.env ]; then
  echo "Aktualisiere /etc/domudns/env..."
  sudo cp /tmp/domudns.env /etc/domudns/env
  sudo chmod 640 /etc/domudns/env
  sudo chown root:root /etc/domudns/env
  rm -f /tmp/domudns.env
elif [ ! -f /etc/domudns/env ]; then
  # Leere env-Datei anlegen damit der Service startet
  sudo touch /etc/domudns/env
  sudo chmod 640 /etc/domudns/env
fi

# Config bei jedem Deployment installieren
if [ -f /tmp/config.yaml ]; then
  echo "Installiere config.yaml..."
  sudo cp /tmp/config.yaml /etc/domudns/config.yaml
  sudo chmod 644 /etc/domudns/config.yaml
  rm -f /tmp/config.yaml
fi

# Service-Datei bei jedem Deployment aktualisieren
echo "Aktualisiere systemd Service-Datei..."
sudo cp /tmp/domudns.service /etc/systemd/system/domudns.service
sudo chmod 644 /etc/systemd/system/domudns.service
sudo systemctl daemon-reload

# Service beim ersten Mal aktivieren
if ! sudo systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
  sudo systemctl enable ${SERVICE_NAME}
  echo "Service ${SERVICE_NAME} aktiviert"
fi

# Service starten/neustarten
echo "Starte Service..."
if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
  sudo systemctl restart ${SERVICE_NAME}
else
  sudo systemctl start ${SERVICE_NAME}
fi

# Warte kurz auf Service-Start
sleep 3

# Service-Status prüfen
if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
  echo "Service läuft"
  sudo systemctl status ${SERVICE_NAME} --no-pager -l
else
  echo "Service konnte nicht gestartet werden!"
  sudo journalctl -u ${SERVICE_NAME} -n 50 --no-pager
  exit 1
fi

# Temporäre Dateien löschen
rm -f /tmp/${BINARY_NAME}
rm -f /tmp/domudns.service

EOF

SSH_EXIT=$?
set -e  # Wieder strikt
if [ $SSH_EXIT -ne 0 ]; then
  echo "SSH-Block endete mit Exit Code $SSH_EXIT"
  exit 1
fi

# 3. Health Check
echo "Health Check..."
sleep 5

HEALTH_URL=""
if curl -f -s -o /dev/null -w "%{http_code}" --max-time 5 https://${PI_HOST}:443/api/health 2>/dev/null | grep -q "200"; then
  HEALTH_URL="https://${PI_HOST}:443/api/health"
elif curl -f -s -o /dev/null -w "%{http_code}" --max-time 5 http://${PI_HOST}:80/api/health 2>/dev/null | grep -q "200"; then
  HEALTH_URL="http://${PI_HOST}:80/api/health"
fi

if [ -n "${HEALTH_URL}" ]; then
  echo "Health Check erfolgreich: ${HEALTH_URL}"
else
  echo "Health Check fehlgeschlagen (weder Port 443 noch Port 80 erreichbar)!"
  ssh ${PI_USER}@${PI_HOST} "sudo systemctl status ${SERVICE_NAME} --no-pager" || true
  exit 1
fi

echo ""
echo "Deployment auf $PI_HOST erfolgreich abgeschlossen!"
echo "================================================"
