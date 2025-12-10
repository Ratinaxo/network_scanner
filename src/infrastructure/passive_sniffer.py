#!/usr/bin/python3
from scapy.all import sniff, ARP, DHCP, BOOTP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw
import re
import time
import os
import sys
from typing import Optional

# Importamos utilidades
import config
from src.utils import log

class PassiveSniffer:
    def __init__(self, interface: str, repository=None, log_path=None):
        """
        Inicializa el Sniffer.
        :param log_path: Ruta específica para el log del sniffer.
        """
        self.interface = interface
        self.repo = repository
        self.log_path = log_path # Log separado
        
        self.dns_cooldown = 300
        self.ttl_cache = {}
        self.dns_cache = {}
        self.ua_pattern = re.compile(b"User-Agent: (.*?)\r\n")

    def _log(self, msg):
        """Wrapper interno para loguear a consola y archivo."""
        print(msg) # Ver en vivo
        log(msg, self.log_path) # Guardar en disco

    def _process_dhcp(self, pkt):
        if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
            return
            
        mac = pkt[Ether].src if pkt.haslayer(Ether) else pkt[BOOTP].chaddr
        fingerprint = []
        hostname = None
        
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple):
                if opt[0] == 'param_req_list':
                    val = opt[1]
                    if isinstance(val, bytes): fingerprint = [b for b in val]
                    elif isinstance(val, list): fingerprint = val
                    else: fingerprint = [int(x) for x in val]
                elif opt[0] == 'hostname':
                    try: hostname = opt[1].decode('utf-8', errors='ignore')
                    except: hostname = str(opt[1])

        if fingerprint:
            sig_str = ",".join(str(x) for x in fingerprint)
            self._log(f"PASSIVE [DHCP] MAC: {mac} | Host: {hostname} | Sig: [{sig_str}]")

    def _process_dns(self, pkt):
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
        try: qname = pkt[DNSQR].qname.decode('utf-8').lower()
        except: return

        src_ip = pkt[IP].src
        if "in-addr.arpa" in qname or ".local" in qname: return

        cache_key = f"{src_ip}|{qname}"
        last_seen = self.dns_cache.get(cache_key, 0)
        now = time.time()

        if (now - last_seen) > self.dns_cooldown:
            self.dns_cache[cache_key] = now
            ecosystem = "Unknown"
            if "apple.com" in qname: ecosystem = "Apple"
            elif "google.com" in qname: ecosystem = "Google"
            elif "windows" in qname: ecosystem = "Windows"
            elif "netflix" in qname: ecosystem = "Streaming"
            
            self._log(f"PASSIVE [DNS] IP: {src_ip} -> {qname} ({ecosystem})")

    def _process_ttl(self, pkt):
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        os_guess = "Unknown"
        if ttl <= 64: os_guess = "Linux/Android/iOS"
        elif ttl <= 128: os_guess = "Windows"
        elif ttl <= 255: os_guess = "Cisco/Network"

        if src_ip not in self.ttl_cache:
            self.ttl_cache[src_ip] = ttl
            self._log(f"PASSIVE [TTL] IP: {src_ip} | TTL: {ttl} ({os_guess})")
        elif self.ttl_cache[src_ip] != ttl:
            old = self.ttl_cache[src_ip]
            self.ttl_cache[src_ip] = ttl
            self._log(f"PASSIVE [TTL CHANGE] IP: {src_ip} | {old} -> {ttl}")

    def _process_http(self, pkt):
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"User-Agent:" in payload:
                match = self.ua_pattern.search(payload)
                if match:
                    try:
                        ua = match.group(1).decode('utf-8', errors='ignore')
                        self._log(f"PASSIVE [HTTP] IP: {pkt[IP].src} | UA: {ua}")
                    except: pass

    def _packet_callback(self, pkt):
        try:
            if pkt.haslayer(IP):
                self._process_ttl(pkt)
                if pkt.haslayer(UDP) and pkt[UDP].dport == 53: self._process_dns(pkt)
                if pkt.haslayer(TCP) and pkt[TCP].dport == 80: self._process_http(pkt)
            if pkt.haslayer(UDP) and (pkt[UDP].sport == 68 or pkt[UDP].dport == 67):
                 self._process_dhcp(pkt)
        except Exception: pass

    def start(self):
        """Inicia el bucle de captura."""
        msg = f"[*] Starting Passive Sniffer on {self.interface}..."
        print(msg)
        log(msg, self.log_path)
        print(f"[*] Logging to: {self.log_path}")
        
        try:
            sniff(prn=self._packet_callback, filter="ip or arp", store=0, iface=self.interface)
        except Exception as e:
            err = f"CRITICAL SNIFFER ERROR: {e}"
            print(err)
            log(err, self.log_path)

# --- BLOQUE DE EJECUCIÓN MANUAL ---
if __name__ == "__main__":
    # 1. Configuración de Rutas (Para que funcione desde cualquier lugar)
    # Calculamos la raíz del proyecto basándonos en la ubicación de este archivo
    current_dir = os.path.dirname(os.path.abspath(__file__)) # src/infrastructure
    src_dir = os.path.dirname(current_dir) # src
    root_dir = os.path.dirname(src_dir) # network_scanner
    
    # Definimos dónde guardar el log específico
    sniffer_log_file = os.path.join(root_dir, "logs", "sniffer.log")
    
    # 2. Detección de Interfaz
    # Intentamos detectar, si falla usamos 'enp2s0' por defecto (tu interfaz)
    iface = "enp2s0" 
    try:
        import subprocess, shlex
        out = subprocess.check_output(shlex.split("ip route get 1.1.1.1"), text=True)
        parts = out.split()
        if "dev" in parts:
            iface = parts[parts.index("dev") + 1]
    except:
        pass
    # 3. Lanzar
    print(f"--- SNIFFER LAUNCHER ---")
    print(f"Root Dir: {root_dir}")
    print(f"Interface: {iface}")
    
    sniffer = PassiveSniffer(interface=iface, log_path=sniffer_log_file)
    sniffer.start()