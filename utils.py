import datetime
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