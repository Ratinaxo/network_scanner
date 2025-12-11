def determine_type(repo, device_id: int) -> str:
    """
    Determina el tipo de dispositivo.
    """
    # 1. Obtener datos
    data = repo.get_device_details(device_id)
    
    os_name = data["os"].lower()
    open_ports = data["ports"]
    # Juntamos todo el texto descriptivo en una sola variable para búsquedas fáciles
    # (scripts_data ya está incluido en 'banners' si usas el repositorio actualizado, 
    # pero por si acaso lo traemos explícito si tu repo no lo junta)
    full_text = (data["banners"] + " " + repo.get_scripts_output(device_id)).lower()
    vendor = data["vendor"]
    hostname = data["hostname"]

    # --- REGLA 1: EVIDENCIA EN EL HOSTNAME (Muy fuerte) ---
    if "iphone" in hostname: return "mobile_ios"
    if "ipad" in hostname: return "tablet_ios"
    if "macbook" in hostname or "imac" in hostname: return "mac_computer"
    if "android" in hostname: return "android_device"
    if "tv" in hostname or "bravia" in hostname: return "smart_tv"
    
    # --- REGLA 2: EVIDENCIA DE SCRIPTS/BANNERS ---
    # Windows
    if "windows" in full_text and "smb" in full_text:
        if "server" in full_text: return "server_windows"
        return "pc_windows"

    # Impresoras
    if "laserjet" in full_text or "epson" in full_text or 9100 in open_ports:
        return "printer"

    # IoT
    if "hue" in full_text: return "iot_hub"
    if "roku" in full_text or "chromecast" in full_text or 8009 in open_ports:
        return "smart_tv_stick"
    if "sonos" in full_text: return "audio_device"
    
    # Routers
    if "gateway" in full_text or "router" in full_text: return "router"
    if 53 in open_ports and (80 in open_ports or 443 in open_ports): return "router"

    # --- REGLA 3: SISTEMAS OPERATIVOS (Refinada) ---
    
    # APPLE (La parte difícil)
    if "macos" in os_name or "osx" in os_name or "ios" in os_name or "darwin" in os_name:
        # ¿Tiene puertos de escritorio?
        # 22 (SSH), 445 (SMB), 548 (AFP), 5900 (VNC), 3283 (Remote Desktop)
        if any(p in open_ports for p in [22, 445, 548, 5900, 3283]):
            return "mac_computer"
        
        # Si no tiene puertos de "trabajo", asumimos móvil/genérico
        return "apple_device"

    # Windows
    if "windows" in os_name: return "pc_windows"
    
    # Móviles
    if "android" in os_name: return "android_device"

    # Linux Genérico
    if "linux" in os_name:
        if 22 in open_ports: return "linux_device" # Probable server/rpi
        return "linux_device" 

    # --- REGLA 4: VENDOR ---
    if "apple" in vendor: return "apple_device"
    if "espressif" in vendor: return "esp_iot"
    if "raspberry" in vendor: return "raspberry_pi"
    if "nintendo" in vendor: return "gaming_console"

    return "unknown"