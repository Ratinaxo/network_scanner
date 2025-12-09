import datetime
import shlex
import subprocess
import config

def now_iso() -> str:
    """Retorna la fecha y hora actual en formato ISO 8601 UTC."""
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat() + "Z"

def log(msg: str):
    """
    Escribe un mensaje con timestamp en el archivo definido en config.LOG_PATH.
    Si config.LOG_PATH no está definido, no hace nada.
    """
    if not config.LOG_PATH:
        return

    ts = datetime.datetime.now(datetime.UTC).isoformat()
    try:
        with open(config.LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        # Fallo silencioso para no detener el programa si el disco está lleno o hay error de permisos
        pass

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
