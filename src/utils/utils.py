import datetime
import shlex
import subprocess
import config
import os
import fcntl

def now_iso() -> str:
    """Retorna la fecha y hora actual en formato ISO 8601 UTC."""
    return datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()

def log(msg: str, log_file: str = None):
    """
    Escribe un mensaje con timestamp.
    :param msg: El mensaje a escribir.
    :param log_file: Ruta absoluta del archivo log. Si es None, usa el default de config.
    """
    target_file = log_file if log_file else config.SCANNER_LOG_PATH
    
    if not target_file:
        return

    ts = now_iso()
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

class ProcessLock:
    def __init__(self, lock_file_path=None):
        self.lock_file_path = lock_file_path if lock_file_path else config.LOCK_FILE_PATH
        self.fp = None

    def acquire(self):
        """Intenta adquirir el bloqueo. Retorna True si tiene éxito, False si ya está ocupado."""
        try:
            os.makedirs(os.path.dirname(self.lock_file_path), exist_ok=True)

            # Abrimos el archivo de bloqueo (lo crea si no existe)
            self.fp = open(self.lock_file_path, 'w')
            
            # Intentamos bloquearlo EXCLUSIVAMENTE y SIN ESPERAR (LOCK_NB)
            fcntl.lockf(self.fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            
            return True
        except IOError:
            # Si falla, es porque otro proceso ya tiene el candado
            return False

    def release(self):
        """Libera el bloqueo (aunque el OS lo hace solo al morir el proceso)."""
        if self.fp:
            try:
                fcntl.lockf(self.fp, fcntl.LOCK_UN)
                self.fp.close()
                if os.path.exists(self.lock_file_path):
                    os.remove(self.lock_file_path)
            except:
                pass