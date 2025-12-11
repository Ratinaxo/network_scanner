#!/usr/bin/python3
from scapy.all import sniff, ARP, DHCP, BOOTP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw, get_if_addr
import re
import time
import os
import sys
from typing import Optional

# Importamos módulos del proyecto
import config
from src.utils import log
from src.database.connection import DatabaseManager
from src.database.repository import DeviceRepository

class PassiveSniffer:
    def __init__(self, interface: str, repository=None, log_path=None):
        self.interface = interface
        self.repo = repository
        self.log_path = log_path
        
        self.dns_cooldown = 300
        self.ttl_cache = {}
        self.dns_cache = {}
        self.ua_pattern = re.compile(b"User-Agent: (.*?)\r\n")
        self.my_ip = get_if_addr(interface)

    def _log(self, msg):
        """Loguea a consola y archivo."""
        print(msg)
        log(msg, self.log_path)

    def _process_dhcp(self, pkt):
        """Extrae Fingerprint de opciones DHCP."""
        if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
            return
            
        # Intentamos obtener MAC de Ethernet, sino del header BOOTP
        mac = pkt[Ether].src if pkt.haslayer(Ether) else pkt[BOOTP].chaddr
        fingerprint = []
        hostname = None
        
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple):
                if opt[0] == 'param_req_list':
                    val = opt[1]
                    # Normalización de tipos de Scapy
                    if isinstance(val, bytes): fingerprint = [b for b in val]
                    elif isinstance(val, list): fingerprint = val
                    else: fingerprint = [int(x) for x in val]
                elif opt[0] == 'hostname':
                    try: hostname = opt[1].decode('utf-8', errors='ignore')
                    except: hostname = str(opt[1])

        if fingerprint:
            sig_str = ",".join(str(x) for x in fingerprint)
            self._log(f"PASSIVE [DHCP] MAC: {mac} | Host: {hostname} | Sig: [{sig_str}]")
        
            if self.repo:
                self.repo.save_passive_fingerprint(
                    ip=None, # DHCP Discover a veces no tiene IP src válida aún
                    mac=mac, 
                    source="passive_dhcp_opt55", 
                    data=sig_str
                )

    def _process_dns(self, pkt):
        """Analiza ecosistema basado en consultas DNS."""
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
            ecosystem = None
            
            if "apple.com" in qname: ecosystem = "Apple"
            elif "google.com" in qname: ecosystem = "Google"
            elif "windows" in qname or "microsoft" in qname: ecosystem = "Windows"
            elif "netflix" in qname: ecosystem = "Streaming"
            elif "nintendo" in qname: ecosystem = "Nintendo"
            
            if ecosystem:
                self._log(f"PASSIVE [DNS] IP: {src_ip} -> {qname} ({ecosystem})")
                # Opcional: Guardar ecosistema en DB si quieres (usa save_passive_fingerprint con data=ecosystem)

    def _process_ttl(self, pkt):
        """Analiza TTL para inferir OS."""
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        # Intentamos obtener la MAC si está disponible en la capa 2
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        
        os_guess = "Unknown"
        if ttl < 30 or ttl > 200:
            return
        
        if ttl <= 64: os_guess = "Linux/Android/iOS"
        elif ttl <= 128: os_guess = "Windows"
        elif ttl <= 255: os_guess = "Cisco/Network"

        # Lógica de Caché para no saturar DB ni Logs
        if src_ip not in self.ttl_cache:
            self.ttl_cache[src_ip] = ttl
            self._log(f"PASSIVE [TTL] IP: {src_ip} | TTL: {ttl} ({os_guess})")
            
            if self.repo:
                self.repo.save_passive_fingerprint(
                    ip=src_ip, 
                    mac=src_mac, 
                    source="passive_ttl", 
                    data=f"{ttl} ({os_guess})"
                )
                
        elif self.ttl_cache[src_ip] != ttl:
            old = self.ttl_cache[src_ip]
            self.ttl_cache[src_ip] = ttl
            self._log(f"PASSIVE [TTL CHANGE] IP: {src_ip} | {old} -> {ttl}")
            
            if self.repo:
                self.repo.save_passive_fingerprint(
                    ip=src_ip, 
                    mac=src_mac, 
                    source="passive_ttl", 
                    data=f"{ttl} ({os_guess})"
                )

    def _process_http(self, pkt):
        """Captura User-Agent."""
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"User-Agent:" in payload:
                match = self.ua_pattern.search(payload)
                if match:
                    try:
                        ua = match.group(1).decode('utf-8', errors='ignore')
                        self._log(f"PASSIVE [HTTP] IP: {pkt[IP].src} | UA: {ua}")
                        
                        # --- CORRECCIÓN: GUARDAR EN DB ---
                        if self.repo:
                            self.repo.save_passive_fingerprint(
                                ip=pkt[IP].src,
                                mac=pkt[Ether].src if pkt.haslayer(Ether) else None,
                                source="passive_http_ua",
                                data=ua
                            )
                    except: pass

    def _packet_callback(self, pkt):
        try:
            if pkt.haslayer(IP):
                if pkt[IP].src == self.my_ip: 
                    return  # Evitar auto-captura de nuestra propia IP, o se generará ruido por el scanner
                
                self._process_ttl(pkt)
                if pkt.haslayer(UDP) and pkt[UDP].dport == 53: self._process_dns(pkt)
                if pkt.haslayer(TCP) and pkt[TCP].dport == 80: self._process_http(pkt)
            
            if pkt.haslayer(UDP) and (pkt[UDP].sport == 68 or pkt[UDP].dport == 67):
                 self._process_dhcp(pkt)
        except Exception: 
            pass

    def start(self):
        """Inicia el bucle de captura."""
        msg = f"[*] Starting Passive Sniffer on {self.interface}..."
        print(msg)
        log(msg, self.log_path)
        print(f"[*] Logging to: {self.log_path}")
        
        try:
            # store=0 vital para que no se coma la RAM
            sniff(prn=self._packet_callback, filter="ip or arp", store=0, iface=self.interface)
        except Exception as e:
            err = f"CRITICAL SNIFFER ERROR: {e}"
            print(err)
            log(err, self.log_path)

# --- BLOQUE DE EJECUCIÓN MANUAL ---
if __name__ == "__main__":
    print(f"--- SNIFFER LAUNCHER ---")
    print(f"[*] Project Root: {config.BASE_DIR}")
    print(f"[*] Database:     {config.DB_PATH}")
    print(f"[*] Log File:     {config.SNIFFER_LOG_PATH}")

    # 1. Inicialización de Base de Datos
    repo = None
    try:
        db_manager = DatabaseManager(config.DB_PATH)
        db_manager.initialize_schema() 
        conn = db_manager.get_connection()
        repo = DeviceRepository(conn)
        print("[*] Database connection: OK")
    except Exception as e:
        print(f"[!] Database Error: {e}")

    # 2. Detección de Interfaz (Prioridad: .env -> Auto-detect -> Hardcoded)
    iface = config.DEFAULT_INTERFACE 
    
    # Si no está en .env o es default 'eth0' y queremos ser inteligentes:
    if iface == "eth0":
        try:
            import subprocess, shlex
            out = subprocess.check_output(shlex.split("ip route get 1.1.1.1"), text=True)
            if "dev" in out:
                parts = out.split()
                iface = parts[parts.index("dev") + 1]
        except:
            pass
            
    print(f"[*] Interface:    {iface}")

    # 3. Lanzar
    # Usamos config.SNIFFER_LOG_PATH que viene de tu config.py
    sniffer = PassiveSniffer(interface=iface, repository=repo, log_path=config.SNIFFER_LOG_PATH)
    sniffer.start()