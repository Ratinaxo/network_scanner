import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import sys

def parse_nmap_xml(xml_text: str) -> List[Dict[str, Any]]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"ERROR: No se pudo parsear el XML de Nmap: {e}", file=sys.stderr)
        return hosts
    
    for host in root.findall("host"):
        addr_ipv4 = None
        addr_mac = None
        vendor = None
        hostname = None
        
        status = host.find("status")
        state = status.get("state") if status is not None else None

        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                addr_ipv4 = addr.get("addr")
            elif atype == "mac":
                addr_mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            h = hostnames.find("hostname")
            if h is not None:
                hostname = h.get("name")
        
        # 1. OS Detection
        os_list = []
        os_tree = host.find("os")
        if os_tree is not None:
            for osmatch in os_tree.findall("osmatch"):
                os_list.append({
                    "name": osmatch.get("name"),
                    "accuracy": int(osmatch.get("accuracy") or 0)
                })
        
        # 2. Ports & Services
        ports_list = []
        ports_tree = host.find("ports")
        if ports_tree is not None:
            for port in ports_tree.findall("port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                
                # Estado del puerto (open, closed, filtered)
                p_state = port.find("state")
                state_val = p_state.get("state") if p_state is not None else "unknown"
                
                # Si no está abierto, a veces no nos interesa para fingerprinting, 
                # pero guardémoslo si Nmap lo reporta explícitamente.
                if state_val != "open":
                    continue

                service = port.find("service")
                service_name = service.get("name") if service is not None else None
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                
                ports_list.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        hosts.append({
            "ip": addr_ipv4,
            "mac": addr_mac,
            "vendor": vendor,
            "hostname": hostname,
            "state": state,
            "os_match": os_list,
            "ports": ports_list
        })
    return hosts