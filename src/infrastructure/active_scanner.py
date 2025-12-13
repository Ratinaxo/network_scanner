#!/usr/bin/python3
import subprocess
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

    def scan(self, target, raw_output_path: Optional[str] = None, mode: str = "fast") -> str:
        """
        Ejecuta el escaneo.
        :param target: Puede ser un string ("192.168.1.0/24") o una lista de IPs ["1.1.1.1", "1.2.3.4"]
        """
        cmd = self._build_command(target, raw_output_path, mode)
        
        try:
            process = subprocess.run(cmd, capture_output=True, text=True)
            if process.returncode != 0:
                raise NmapError(f"Nmap falló (Code {process.returncode}): {process.stderr.strip()}")
            return process.stdout
        except OSError as e:
            raise NmapError(f"Error del Sistema: {e}")
    
    def _build_command(self, target, output_path: Optional[str], mode: str) -> List[str]:
        # Base común
        cmd = ["nmap", "-O", "-sS", "-sV", "-R"]
        
        if mode == "deep":
            # --- MODO AGRESIVO FOCALIZADO ---
            # Idealmente 'target' aquí es una lista de IPs específicas
            cmd.extend([
                "--version-intensity", "6",    # Máxima intensidad
                "--top-ports", "1000",         # Compromiso bueno (cubre DBs, Juegos, IoT raro)
                "--script", "discovery,safe",  # Scripts profundos
                "--script-args", "http-spider-maxpagecount=10",
                "-T4",                         # Timing agresivo (porque son pocas IPs)
                "--max-retries", "2",
                "--open"                       # Solo nos interesan puertos abiertos en el reporte
            ])
        else:
            # --- MODO RÁPIDO (BARRIDO) ---
            cmd.extend([
                "--version-intensity", "2",
                f"--top-ports", str(config.TOP_PORTS),
                "--max-retries", "1",
                "--host-timeout", "2m",
                "--script", "broadcast-dhcp-discover,smb-os-discovery,dns-service-discovery,http-title,ssl-cert,upnp-info",
                "--script-timeout", "10s"
            ])

        cmd.extend(["-oX", "-"])
        
        if output_path:
            cmd.extend(["-oN", output_path])
        
        # LÓGICA HÍBRIDA: Lista o String
        if isinstance(target, list):
            # Si es lista, agregamos cada IP como un argumento separado
            cmd.extend(target)
        else:
            # Si es string (subnet), lo agregamos directo
            cmd.append(target)
            
        return cmd