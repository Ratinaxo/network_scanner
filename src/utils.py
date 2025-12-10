import datetime
import shlex
import subprocess
import config
import os
def now_iso() -> str:
    """Retorna la fecha y hora actual en formato ISO 8601 UTC."""
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat() + "Z"

def log(msg: str, log_file: str = None):
    """
    Escribe un mensaje con timestamp.
    :param msg: El mensaje a escribir.
    :param log_file: Ruta absoluta del archivo log. Si es None, usa el default de config.
    """
    target_file = log_file if log_file else config.LOG_PATH
    
    if not target_file:
        return

    ts = datetime.datetime.now(datetime.UTC).isoformat()
    try:
        # Aseguramos que el directorio exista antes de escribir
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        
        with open(target_file, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")
    except Exception as e:
        print(f"Error escribiendo log: {e}") # Feedback en consola si falla el disco

def detect_subnet():
    try:
        out = subprocess.check_output(shlex.split("ip route get 1.1.1.1"), text=True)
        parts = out.split()
        if "src" in parts:
            src_ip = parts[parts.index("src") + 1]
            base = ".".join(src_ip.split(".")[:3]) + ".0/24"
            return base
        return None
    except Exception as e:
        log(f"ERROR detect_subnet: {e}")
        return None
