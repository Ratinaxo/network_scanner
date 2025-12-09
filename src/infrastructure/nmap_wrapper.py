import config, src.utils as utils
from typing import Optional
import subprocess
import sys

def scan(subnet: str, raw_output_path: Optional[str] = None) -> str:
    cmd = [
        "nmap", 
        "-O",             # Detección de Sistema Operativo
        "-sS",            # TCP SYN Scan (Rápido y sigiloso, requiere sudo)
        "-sV",            # Detección de Versiones (Para saber si es Apache, Nginx, etc.)
        "--version-intensity", config.VERSION_INTENSITY, # (Opcional) 0-9. 1 es rápido, 9 es lento pero preciso.
        "-R",             # DNS Resolution (Reverse lookup siempre)
        "--top-ports", config.TOP_PORTS, # AUMENTADO: 20 es muy poco para fingerprinting único. 100 es buen balance.
        "--script", "broadcast-dhcp-discover", # Mantiene la detección de MACs robusta
        "-oX", "-",       # Salida XML a stdout
        subnet]
    
    if raw_output_path:
        cmd.insert(-1, "-oN") # Salida txt a output
        cmd.insert(-1, raw_output_path)

    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if p.returncode != 0:
            utils.log(f"ERROR nmap: {p.stderr.strip()}")
            print("nmap error output:", p.stderr.strip(), file=sys.stderr)
            sys.exit(1)
    
        return p.stdout
    except FileNotFoundError:
        utils.log("ERROR: nmap no está instalado o no se encuentra en el PATH.")
        print("ERROR: nmap no está instalado o no se encuentra en el PATH.", file=sys.stderr)
        sys.exit(1)
