#!/usr/bin/python3
import sys
import os
import subprocess
import config

# Agregamos la raíz al path de Python
if config.ROOT_DIR not in sys.path:
    sys.path.insert(0, config.ROOT_DIR)

# Cambiamos el directorio de trabajo a la raíz para que .env se cargue bien
os.chdir(config.ROOT_DIR)

print(f"[*] Server Starting...")
print(f"[*] Root Dir detected: {config.ROOT_DIR}")
# -------------------------------------------

from flask import Flask, jsonify, render_template
import datetime

# Imports del proyecto
try:
    import config
    from src.database.connection import DatabaseManager
    from src.database.repository import DeviceRepository
    from src.analysis import classifier
    import src.utils.utils as utils
    print("[*] Imports successful")
except ImportError as e:
    print(f"[!] CRITICAL IMPORT ERROR: {e}")
    sys.exit(1)

class WebDashboard:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        self.host = host
        self.port = port
        self.debug = debug
        
        # Configuración explícita de carpetas de Flask
        # Como estamos en src/web/server.py, las plantillas están aquí mismo
        self.template_dir = os.path.join(config.WEB_DIR, 'templates')
        self.static_dir = os.path.join(config.WEB_DIR, 'static')
        
        print(f"[*] Templates Dir: {self.template_dir}")
        
        self.app = Flask(__name__, template_folder=self.template_dir, static_folder=self.static_dir)
        self._register_routes()
        self.db_manager = DatabaseManager(config.DB_PATH)

    def _register_routes(self):
        self.app.add_url_rule('/', view_func=self.index)
        self.app.add_url_rule('/api/device/<int:device_id>', view_func=self.get_device_details)
        self.app.add_url_rule('/scan/trigger/<mode>', view_func=self.trigger_scan, methods=['POST'])
        self.app.add_url_rule('/scan/stop', view_func=self.stop_scan, methods=['POST'])
        self.app.add_url_rule('/api/status', view_func=self.get_system_status)

    def get_system_status(self):
        """Devuelve si hay archivo lock."""
        is_scanning = os.path.exists(config.LOCK_FILE_PATH)
        return jsonify({"scanning": is_scanning})

    def trigger_scan(self, mode):
        """Lanza el escáner en un proceso separado."""
        test_lock = utils.ProcessLock()
        if not test_lock.acquire():
            return jsonify({
                "status": "busy", 
                "message": "Hay un escaneo en curso. Espera a que termine."
            }), 409 # Conflict
        test_lock.release()

        try:
            # Rutas absolutas (Vital para systemd)
            # Asumimos que estamos en src/web/server.py
            wrapper_path = os.path.join(config.SCRIPTS_DIR, "run_scan.sh")
            cmd = ["sudo", wrapper_path]
            
            if mode == "deep":
                cmd.append("--deep")
            
            # Ejecutamos en segundo plano (Popen) para no bloquear la web
            # stdout a DEVNULL para no llenar logs del webserver
            subprocess.Popen(cmd, cwd=config.ROOT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return jsonify({"status": "success", "message": f"Escaneo {mode.upper()} iniciado. Los resultados aparecerán pronto."})
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    def stop_scan(self):
        """Detiene forzosamente cualquier escaneo en curso."""
        
        try:
            # Calculamos la ruta absoluta al script kill_scan.sh
            # Asumiendo estructura: network_scanner/src/web/server.py -> network_scanner/kill_scan.sh
            script_path = os.path.join(config.SCRIPTS_DIR, "kill_scan.sh")
            
            if not os.path.exists(script_path):
                return jsonify({"status": "error", "message": "No se encontró kill_scan.sh"}), 500

            # Ejecutamos con sudo (ya autorizado en sudoers)
            result = subprocess.run(["sudo", script_path], capture_output=True, text=True)
            
            if result.returncode == 0:
                return jsonify({"status": "success", "message": "Escaneo detenido correctamente."})
            else:
                return jsonify({"status": "error", "message": f"Error al detener: {result.stderr}"}), 500
                
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    def get_device_details(self, device_id):
        try:
            with self.db_manager.get_connection() as conn:
                repo = DeviceRepository(conn)
                raw_data = repo.get_device_details(device_id)
                
                ports_list = list(raw_data['ports'])
                ports_list.sort()
                banners = raw_data['banners']
            
            return jsonify({
                "os": raw_data['os'],
                "vendor": raw_data['vendor'],
                "hostname": raw_data['hostname'],
                "open_ports": ports_list,
                "banners_preview": banners[:500] + "..." if len(banners) > 500 else banners
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    def index(self):
        try:
            with self.db_manager.get_connection() as conn:
                repo = DeviceRepository(conn)
                devices = repo.get_dashboard_data()
                now = utils.now_iso()
                last_scan = repo.get_last_scan_time()
                stats = {
                    "total": len(devices), 
                    "online": 0, 
                    "routers": 0, 
                    "unknown": 0,
                    }
                for d in devices:
                    self._process_device_display(d, now, stats)
                return render_template('dashboard.html', devices=devices, stats=stats, last_scan=last_scan)
        except Exception as e:
            return f"<h1>Error conectando a la BD: {e}</h1><p>Verifica conexión con la base de datos.</p>", 500

    def _process_device_display(self, d, now, stats):
        try:
            # 1. Si viene con Z (UTC antiguo), la quitamos
            date_str = d['last_seen'].replace("Z", "")
            
            # 2. Convertimos a objeto datetime
            last_seen = datetime.datetime.fromisoformat(date_str)
            
            # 3. Si la fecha no tiene zona horaria (naive), asumimos la local o UTC según corresponda
            # Para comparar peras con peras, convertimos 'now' (que es UTC) al mismo timezone que last_seen
            if last_seen.tzinfo is None:
                # Si es data vieja sin zona, asumimos UTC para no romper nada
                last_seen = last_seen.replace(tzinfo=datetime.timezone.utc)
            
            # Comparamos
            diff = (datetime.datetime.now(last_seen.tzinfo) - last_seen).total_seconds()
            
            # ... (Resto de la lógica igual) ...
            d['is_online'] = diff < 600
            
            if diff < 60: d['last_seen_str'] = "Hace un momento"
            elif diff < 3600: d['last_seen_str'] = f"Hace {int(diff/60)} min"
            elif diff < 86400: d['last_seen_str'] = f"Hace {int(diff/3600)} horas"
            else: d['last_seen_str'] = last_seen.strftime("%Y-%m-%d %H:%M")

            d['is_deep_scanned'] = False
            if d['last_deep_scan']:
                d['is_deep_scanned'] = True
                
        except Exception:
            d['is_online'] = False
            d['last_seen_str'] = "N/A"

        d['icon'] = "question-circle"; d['color'] = "secondary"
        t = str(d['type']).lower()
        
        if 'router' in t or 'gateway' in t: d['icon'] = "router"; d['color'] = "danger"; stats['routers'] += 1
        elif 'apple' in t or 'mac' in t or 'ios' in t: d['icon'] = "apple"; d['color'] = "dark"
        elif 'windows' in t: d['icon'] = "windows"; d['color'] = "primary"
        elif 'linux' in t: d['icon'] = "terminal"; d['color'] = "warning text-dark"
        elif 'android' in t: d['icon'] = "android2"; d['color'] = "success"
        elif 'tv' in t or 'stick' in t: d['icon'] = "tv"; d['color'] = "info text-dark"
        elif 'printer' in t: d['icon'] = "printer"; d['color'] = "secondary"
        elif 'game' in t or 'console' in t: d['icon'] = "controller"; d['color'] = "success"

        if d['is_online']: stats['online'] += 1
        if d['type'] == 'unknown': stats['unknown'] += 1
    
        # 4. Barra de confianza: Llamamos al clasificador para obtener el score actual
        confidence = d.get('confidence', 0)

        # Color de la barra según confianza
        if confidence > 80: d['conf_color'] = "success"
        elif confidence > 50: d['conf_color'] = "warning"
        else: d['conf_color'] = "danger"

        d['is_deep_scanned'] = False
        if d.get('last_deep_scan'):
            try:
                # Parseamos la fecha del deep scan
                deep_str = d['last_deep_scan'].replace("Z", "")
                last_deep = datetime.datetime.fromisoformat(deep_str)
                if last_deep.tzinfo is None:
                    last_deep = last_deep.replace(tzinfo=datetime.timezone.utc)
                
                # Calculamos antigüedad
                deep_age = (now - last_deep).total_seconds()
                
                # REGLA DE VIGENCIA: 
                # Consideramos válido el Deep Scan si ocurrió hace menos de 7 días (604800 segundos)
                # Puedes cambiar este valor según tu preferencia.
                DIAS_VIGENCIA = 1
                if deep_age < (DIAS_VIGENCIA * 24 * 3600):
                    d['is_deep_scanned'] = True
                    
                    # (Opcional) Formato bonito para el tooltip
                    # Si fue hoy, muestra la hora, sino la fecha
                    if deep_age < 86400:
                        d['last_deep_scan'] = f"Hoy a las {last_deep.strftime('%H:%M')}"
                    else:
                        d['last_deep_scan'] = f"Hace {int(deep_age/86400)} días"
                else:
                    # Si es muy viejo, lo marcamos como falso para que no salga el escudo
                    d['is_deep_scanned'] = False 
            except:
                d['is_deep_scanned'] = False


    def run(self):
        print(f"[*] Iniciando Flask en port {self.port}...")
        self.app.run(host=self.host, port=self.port, debug=self.debug)

if __name__ == '__main__':
    try:
        db_manager = DatabaseManager(config.DB_PATH)
        db_manager.initialize_schema()

        with db_manager.get_connection() as conn:
            repo = DeviceRepository(conn)
            print(f"[*] Repository Check: OK (Devices: {len(repo.get_dashboard_data())})")

    except Exception as e:
        utils.log(f"CRITICAL DB ERROR: {e}")
        print(f"Error inicializando DB en {config.DB_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        dashboard = WebDashboard(debug=True)
        dashboard.run()
    except Exception as e:
        print(f"[!] Error fatal iniciando dashboard: {e}")