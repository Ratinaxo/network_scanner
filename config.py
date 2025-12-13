import os
import pwd
from dotenv import load_dotenv

# 1. Cargar variables del archivo .env
# Buscamos el .env en el directorio actual o padres
load_dotenv()

# 2. Definir la Raíz del Proyecto (Calculada dinámicamente desde la ubicación de este archivo)
# Si config.py está en la raíz, ROOT_DIR es la raíz.
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# 3. Función auxiliar para construir rutas absolutas
def get_path(env_key, default_folder):
    """
    Obtiene una ruta del .env. Si es relativa, la une con ROOT_DIR.
    Si no existe en .env, usa el default.
    """
    path_str = os.getenv(env_key, default_folder)
    if os.path.isabs(path_str):
        return path_str
    return os.path.join(ROOT_DIR, path_str)

def ensure_dir_owner(path, owner_user="ratin"):
    """
    Crea el directorio y, si somos root, le asignamos la propiedad
    al usuario normal para evitar problemas de permisos.
    """
    # 1. Crear directorio (si no existe)
    os.makedirs(path, exist_ok=True)
    
    # 2. Si estamos corriendo como root (UID 0), arreglamos los permisos
    if os.geteuid() == 0:
        try:
            # Obtenemos el UID y GID del usuario
            user_info = pwd.getpwnam(owner_user)
            uid = user_info.pw_uid
            gid = user_info.pw_gid
            
            # Cambiamos el dueño de la carpeta
            os.chown(path, uid, gid)
            
            # (Opcional) Permisos rwxr-xr-x
            os.chmod(path, 0o755)
            # print(f"[*] Permisos corregidos para: {path}")
        except KeyError:
            print(f"[!] Advertencia: Usuario '{owner_user}' no encontrado. Carpetas quedaron como root.")
        except Exception as e:
            print(f"[!] Error cambiando permisos de {path}: {e}")

# --- RUTAS DE SISTEMA (Absolutas garantizadas) ---
DATA_DIR = get_path("DATA_DIR", "data")
LOGS_DIR = get_path("LOGS_DIR", "logs")
SCANS_DIR = get_path("SCANS_DIR", "scans")
WEB_DIR = get_path("WEB_DIR", os.path.join("src", "web"))
SCRIPTS_DIR = get_path("SCRIPTS_DIR", os.path.join("src", "scripts"))

# Aseguramos que existan
ensure_dir_owner(DATA_DIR)
ensure_dir_owner(LOGS_DIR)
ensure_dir_owner(SCANS_DIR)

# Archivos específicos
DB_FILENAME = "devices.db"
SCANNER_LOG_FILENAME = "tracker.log"
SNIFFER_LOG_FILENAME = "sniffer.log"
LOCK_FILENAME = "network_tracker.lock"

LOCK_FILE_PATH = os.path.join(DATA_DIR, LOCK_FILENAME)
DB_PATH = os.path.join(DATA_DIR, DB_FILENAME)
SCANNER_LOG_PATH = os.path.join(LOGS_DIR, SCANNER_LOG_FILENAME)
SNIFFER_LOG_PATH = os.path.join(LOGS_DIR, SNIFFER_LOG_FILENAME)

# --- CONFIGURACIÓN DE RED ---
FORCE_SUBNET = os.getenv("NETWORK_SUBNET") # Puede ser None
DEFAULT_INTERFACE = os.getenv("DEFAULT_INTERFACE", "eth0")

# --- CONFIGURACIÓN NMAP ---
TOP_PORTS = os.getenv("NMAP_TOP_PORTS", "100")
VERSION_INTENSITY = os.getenv("NMAP_VERSION_INTENSITY", "4")
DEEP_SCAN_MINUTES_SEEN = int(os.getenv("DEEP_SCAN_MINUTES_SEEN", "10"))
