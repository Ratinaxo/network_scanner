import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import sys

def parse_xml(xml_text: str) -> List[Dict[str, Any]]:
    """
    Transforma el XML de Nmap en una lista de diccionarios.
    """
    hosts = []
    
    try:
        # Intentamos parsear el XML
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"[PARSER ERROR] XML mal formado: {e}", file=sys.stderr)
        return []
    
    # DEBUG: Ver si el XML tiene contenido
    # print(f"[PARSER DEBUG] XML size: {len(xml_text)} bytes")

    for host in root.findall("host"):
        # Ignorar hosts que no están "up"
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # --- 1. Identificación ---
        addr_ipv4 = None
        addr_mac = None
        vendor = None
        
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4": addr_ipv4 = addr.get("addr")
            elif atype == "mac": 
                addr_mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            h = hostnames.find("hostname")
            if h is not None: hostname = h.get("name")

        # --- 2. Extracción de Scripts (Host & Puertos) ---
        scripts_results = []

        # A. Host Scripts (ej: smb-os-discovery, nbstat)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid = script.get("id")
                out = script.get("output")
                if sid and out:
                    scripts_results.append({"id": sid, "output": out})
                    # DEBUG VISUAL
                    print(f"   [PARSER] Found Host Script: {sid}")

        # B. Port Scripts (ej: http-title, ssl-cert)
        ports_list = []
        ports_tree = host.find("ports")
        
        if ports_tree is not None:
            for port in ports_tree.findall("port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open": continue

                service = port.find("service")
                service_name = service.get("name") if service is not None else None
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                
                # BUSCAR SCRIPTS DENTRO DEL PUERTO
                for script in port.findall("script"):
                    sid = script.get("id")
                    out = script.get("output")
                    if sid and out:
                        scripts_results.append({"id": sid, "output": out})
                        # DEBUG VISUAL
                        print(f"   [PARSER] Found Port Script ({port_id}): {sid}")

                ports_list.append({
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        # Construcción del objeto
        hosts.append({
            "ip": addr_ipv4,
            "mac": addr_mac,
            "vendor": vendor,
            "hostname": hostname,
            "state": "up",
            "os_match": [], # Simplificado para brevedad, tu código anterior de OS estaba bien
            "ports": ports_list,
            "scripts": scripts_results
        })
        
        # Recuperar OS match (del código anterior)
        os_tree = host.find("os")
        if os_tree is not None:
            for osmatch in os_tree.findall("osmatch"):
                hosts[-1]["os_match"].append({
                    "name": osmatch.get("name"),
                    "accuracy": int(osmatch.get("accuracy") or 0)
                })

    return hosts