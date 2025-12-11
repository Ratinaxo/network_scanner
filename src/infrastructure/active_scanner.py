#!/usr/bin/python3
import subprocess
import sys
import shutil
from typing import Optional, List
import config

class NmapError(Exception):
    """Excepción personalizada para errores de Nmap."""
    pass

class NmapScanner:
    def __init__(self):
        """
        Inicializa el wrapper verificando si nmap existe.
        """
        if not shutil.which("nmap"):
            raise NmapError("El ejecutable 'nmap' no se encuentra en el PATH del sistema.")

    def scan(self, subnet: str, raw_output_path: Optional[str] = None) -> str:
        """
        Ejecuta el escaneo y retorna el XML raw.
        Lanza NmapError si algo falla.
        """
        cmd = self._build_command(subnet, raw_output_path)
        
        try:
            # capture_output=True es el equivalente moderno de stdout=PIPE, stderr=PIPE
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.returncode != 0:
                # No matamos el programa, lanzamos el error hacia arriba
                raise NmapError(f"Nmap falló (Exit Code {process.returncode}): {process.stderr.strip()}")

            return process.stdout

        except OSError as e:
            raise NmapError(f"Error del Sistema al ejecutar nmap: {e}")

    def _build_command(self, subnet: str, output_path: Optional[str]) -> List[str]:
        """Construye la lista de argumentos para Nmap."""
        cmd = [
            "nmap", 
            "-O",             
            "-sS",            
            "-sV",            
            # Bajamos intensidad a 2 (suficiente para banners)
            f"--version-intensity", "2", 
            "-R",             
            f"--top-ports", str(config.TOP_PORTS),
            
            # --- OPTIMIZACIÓN CRÍTICA ---
            "--max-retries", "1",        # No insistir si falla
            "--host-timeout", "2m",      # Timeout por host
            "--min-rate", "100",         # Velocidad mínima
            
            # SCRIPTS QUIRÚRGICOS (Sin 'default' ni 'discovery')
            "--script", "broadcast-dhcp-discover,smb-os-discovery,dns-service-discovery,http-title,ssl-cert,upnp-info",
            "--script-timeout", "10s",   # Matar scripts lentos
            
            "-oX", "-"
        ]

        if output_path:
            cmd.extend(["-oN", output_path])
        
        cmd.append(subnet)
        return cmd