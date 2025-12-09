import os

# --- Configuración de Red ---
# Si quieres fijar manualmente un rango (ej: "192.168.1.0/24"):
FORCE_SUBNET = None

# --- Rutas Dinámicas ---
# Estas variables se inicializan en main.py al arrancar,
# pero las declaramos aquí para que otros módulos puedan importarlas.
DB_PATH = None
LOG_PATH = None

# --- Valores por Defecto ---
DEFAULT_DATA_DIR_NAME = "data"
DEFAULT_LOG_DIR_NAME = "logs"
DEFAULT_SCANS_DIR_NAME = "scans"
DB_FILENAME = "devices.db"
LOG_FILENAME = "tracker.log"

# --- Configuración de Nmap ---
# Puertos top a escanear
TOP_PORTS = "100"
# Intensidad de detección de versiones (0-9)
VERSION_INTENSITY = "5"