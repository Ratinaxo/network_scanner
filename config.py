import os
from dotenv import load_dotenv

# 1. Cargar variables del archivo .env
# Buscamos el .env en el directorio actual o padres
load_dotenv()

# 2. Definir la Raíz del Proyecto (Calculada dinámicamente desde la ubicación de este archivo)
# Si config.py está en la raíz, BASE_DIR es la raíz.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 3. Función auxiliar para construir rutas absolutas
def get_path(env_key, default_folder):
    """
    Obtiene una ruta del .env. Si es relativa, la une con BASE_DIR.
    Si no existe en .env, usa el default.
    """
    path_str = os.getenv(env_key, default_folder)
    if os.path.isabs(path_str):
        return path_str
    return os.path.join(BASE_DIR, path_str)

# --- RUTAS DE SISTEMA (Absolutas garantizadas) ---
DATA_DIR = get_path("DATA_DIR", "data")
LOGS_DIR = get_path("LOGS_DIR", "logs")
SCANS_DIR = get_path("SCANS_DIR", "scans")

# Aseguramos que existan
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(SCANS_DIR, exist_ok=True)

# Archivos específicos
DB_FILENAME = "devices.db"
SCANNER_LOG_FILENAME = "tracker.log"
SNIFFER_LOG_FILENAME = "sniffer.log"

DB_PATH = os.path.join(DATA_DIR, DB_FILENAME)
SCANNER_LOG_PATH = os.path.join(LOGS_DIR, SCANNER_LOG_FILENAME)
SNIFFER_LOG_PATH = os.path.join(LOGS_DIR, SNIFFER_LOG_FILENAME)

# --- CONFIGURACIÓN DE RED ---
FORCE_SUBNET = os.getenv("NETWORK_SUBNET") # Puede ser None
DEFAULT_INTERFACE = os.getenv("DEFAULT_INTERFACE", "eth0")

# --- CONFIGURACIÓN NMAP ---
TOP_PORTS = os.getenv("NMAP_TOP_PORTS", "100")
VERSION_INTENSITY = os.getenv("NMAP_VERSION_INTENSITY", "4")