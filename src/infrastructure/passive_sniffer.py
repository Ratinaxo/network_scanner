#!/usr/bin/python3
from scapy.all import sniff, ARP, DHCP, BOOTP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw, get_if_addr
import re
import time
from typing import Optional
import ipaddress
import sys

# Importamos módulos del proyecto
import config
from src.utils.utils import log
from src.database.connection import DatabaseManager
from src.database.repository import DeviceRepository

class PassiveSniffer:
    def __init__(self, interface: str, db_manager: DatabaseManager, repository=None, log_path=None):
        self.interface = interface
        self.db_manager = db_manager
        self.log_path = log_path
        
        self.dns_cooldown = 300
        self.ttl_cache = {}
        self.dns_cache = {}
        self.ua_pattern = re.compile(b"User-Agent: (.*?)\r\n")
        self.my_ip = get_if_addr(interface)

    def _save_fingerprint(self, ip: Optional[str], mac: str, source: str, data: str):
        """Guarda la huella en la base de datos."""
        try:
            with self.db_manager.get_connection() as conn:
                repo = DeviceRepository(conn)
                repo.save_passive_fingerprint(ip=ip, mac=mac, source=source, data=data)
                conn.commit()
        except Exception as e:
            self._log(f"ERROR saving fingerprint to DB: {e}")

    def _is_local_traffic(self, src_ip):
        """
        Filtro estricto: Solo nos interesa el tráfico que se origina
        DENTRO de nuestra red local (192.168.x.x, 10.x.x.x, etc).
        Ignoramos respuestas que vienen de Internet hacia nosotros.
        """
        try:
            if src_ip == "0.0.0.0": return True # DHCP Request
            ip = ipaddress.ip_address(src_ip)
            return (ip.is_private or ip.is_loopback) and not ip.is_link_local
        except ValueError:
            return False

    def _log(self, msg):
        """Loguea a consola y archivo."""
        print(msg)
        log(msg, self.log_path)

    def _process_dhcp(self, pkt):
        """Extrae Fingerprint de opciones DHCP."""
        if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP): return
        
        # En DHCP Discover, src_ip es 0.0.0.0, lo cual es válido aquí
        src_ip = pkt[IP].src
        
        mac = pkt[Ether].src if pkt.haslayer(Ether) else pkt[BOOTP].chaddr
        if isinstance(mac, bytes): mac = mac.decode('utf-8', errors='ignore')
        
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

        if mac:
            try:
                with self.db_manager.get_connection() as conn:
                    repo = DeviceRepository(conn)
                    # 1. Resolvemos ID
                    dev_id = repo.resolve_device_id(mac, None)
                    
                    # 2. Si no existe, se crea (vía save_passive_fingerprint luego), 
                    # pero si existe, intentamos mejorar el nombre YA MISMO.
                    if dev_id and hostname:
                        repo.update_hostname_if_better(dev_id, hostname)
                        
                    # 3. Guardamos la huella (Esto ya lo hacías)
                    if fingerprint:
                        sig_str = ",".join(str(x) for x in fingerprint)
                        self._log(f"PASSIVE [DHCP] MAC: {mac} | Host: {hostname} | Sig: {sig_str}")
                        repo.save_passive_fingerprint(ip=None, mac=mac, source="passive_dhcp_opt55", data=sig_str)
                        conn.commit()
            except Exception as e:
                self._log(f"DB ERROR in DHCP: {e}")
        

    def _process_dns(self, pkt):     
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)): return
        try: qname = pkt[DNSQR].qname.decode('utf-8').lower()
        except: return

        src_ip = pkt[IP].src
        if "in-addr.arpa" in qname or ".local" in qname: return
        if not self._is_local_traffic(src_ip): return
        
        cache_key = f"{src_ip}|{qname}"
        last_seen = self.dns_cache.get(cache_key, 0)
        now = time.time()

        if (now - last_seen) > self.dns_cooldown:
            self.dns_cache[cache_key] = now
            ecosystem = None
            
            if "apple.com" in qname or "icloud.com" in qname: ecosystem = "Apple Ecosystem"
            elif "google.com" in qname or "android" in qname: ecosystem = "Google Ecosystem"
            elif "windows" in qname or "microsoft" in qname: ecosystem = "Microsoft Ecosystem"
            elif "netflix" in qname: ecosystem = "Streaming (Netflix)"
            elif "nintendo" in qname: ecosystem = "Nintendo"
            elif "playstation" in qname: ecosystem = "PlayStation"
            
            if ecosystem:
                self._log(f"PASSIVE [DNS] IP: {src_ip} -> {ecosystem}")
                # Opcional: Guardar ecosistema
                # self._save_fingerprint(ip=src_ip, mac=None, source="passive_dns_ecosystem", data=ecosystem)

    def _process_ttl(self, pkt):
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        
        if not self._is_local_traffic(src_ip): return
        if src_ip == self.my_ip: return

        os_guess = "Unknown"
        if ttl < 30 or ttl > 200: return # TTLs raros ignorados
        
        if ttl <= 64: os_guess = "Linux/Android/iOS"
        elif ttl <= 128: os_guess = "Windows"
        elif ttl <= 255: os_guess = "Cisco/Network"

        # Caché para evitar escribir en DB 100 veces por segundo
        if src_ip not in self.ttl_cache or self.ttl_cache[src_ip] != ttl:
            self.ttl_cache[src_ip] = ttl
            self._log(f"PASSIVE [TTL] IP: {src_ip} | TTL: {ttl} ({os_guess})")
            
            self._save_fingerprint(
                ip=src_ip, 
                mac=src_mac, 
                source="passive_ttl", 
                data=f"{ttl} ({os_guess})"
            )

    def _process_http(self, pkt):
        src_ip = pkt[IP].src
        if not self._is_local_traffic(src_ip): return
        
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
                if b"User-Agent:" in payload:
                    match = self.ua_pattern.search(payload)
                    if match:
                        ua = match.group(1).decode('utf-8', errors='ignore')
                        self._log(f"PASSIVE [HTTP] IP: {src_ip} | UA: {ua[:50]}...")
                        
                        self._save_fingerprint(
                            ip=src_ip,
                            mac=pkt[Ether].src if pkt.haslayer(Ether) else None,
                            source="passive_http_ua",
                            data=ua
                        )
            except: pass

    def _packet_callback(self, pkt):
        try:
            if pkt.haslayer(IP):
                if pkt[IP].src == self.my_ip: return
                self._process_ttl(pkt)
                if pkt.haslayer(UDP) and pkt[UDP].dport == 53: self._process_dns(pkt)
                if pkt.haslayer(TCP) and pkt[TCP].dport == 80: self._process_http(pkt)
            
            if pkt.haslayer(UDP) and (pkt[UDP].sport == 68 or pkt[UDP].dport == 67):
                 self._process_dhcp(pkt)
        except Exception: 
            pass

    def start(self):
        msg = f"[*] Starting Passive Sniffer on {self.interface}..."
        self._log(msg)
        try:
            # store=0 es vital para daemons de larga duración
            sniff(prn=self._packet_callback, filter="ip or arp", store=0, iface=self.interface)
        except Exception as e:
            self._log(f"CRITICAL SNIFFER ERROR: {e}")

if __name__ == "__main__":
    print(f"--- SNIFFER LAUNCHER ---")
    
    # 1. Configuración de Base de Datos
    # El Sniffer es responsable de instanciar el Manager y pasárselo a la clase
    try:
        db_mgr = DatabaseManager(config.DB_PATH)
        db_mgr.initialize_schema() # Se asegura que existan tablas
        print("[*] DB Connection Manager: Ready")
    except Exception as e:
        print(f"[!] Critical DB Init Error: {e}")
        sys.exit(1)

    # 2. Detección de Interfaz
    iface = config.DEFAULT_INTERFACE 
    if iface == "eth0": # Fallback de auto-detección simple
        try:
            import subprocess, shlex
            out = subprocess.check_output(shlex.split("ip route get 1.1.1.1"), text=True)
            if "dev" in out:
                parts = out.split()
                iface = parts[parts.index("dev") + 1]
        except: pass
            
    # 3. Lanzar
    # NOTA: Pasamos db_mgr, NO repo.
    sniffer = PassiveSniffer(interface=iface, db_manager=db_mgr, log_path=config.SNIFFER_LOG_PATH)
    sniffer.start()