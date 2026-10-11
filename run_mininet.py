#!/usr/bin/env python3
"""
=============================================================================
run_mininet.py — Script de arranque de Mininet
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Uso:
    sudo python3 run_mininet.py

Este script verifica todas las condiciones necesarias antes de
levantar la topología, para evitar errores comunes al correr Mininet.
=============================================================================
"""

import os
import sys
import subprocess
import socket
import time

# ─── CONFIGURACIÓN ───────────────────────────────────────────────────────────
CONTROLLER_IP   = '127.0.0.1'
CONTROLLER_PORT = 6633
TOPOLOGY_SCRIPT = 'topology_project.py'

# ─── COLORES para la consola ──────────────────────────────────────────────────
OK    = '\033[92m[OK]   \033[0m'
WARN  = '\033[93m[WARN] \033[0m'
ERROR = '\033[91m[ERROR]\033[0m'
INFO  = '\033[94m[INFO] \033[0m'
SEP   = '=' * 60


def titulo(texto):
    print(f'\n{SEP}')
    print(f'  {texto}')
    print(SEP)


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICACIONES
# ═══════════════════════════════════════════════════════════════════════════════

def check_root():
    """El script debe correr como root (sudo) porque Mininet lo requiere."""
    if os.geteuid() != 0:
        print(f'\n{ERROR} Este script debe ejecutarse con sudo:\n')
        print('        sudo python3 run_mininet.py\n')
        sys.exit(1)
    print(f'{OK} Ejecutando como root')


def check_mininet():
    """Verifica que Mininet esté instalado."""
    result = subprocess.run(['mn', '--version'],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f'{ERROR} Mininet no está instalado. Instalar con:')
        print('        sudo apt install mininet\n')
        sys.exit(1)
    version = result.stderr.strip() or result.stdout.strip()
    print(f'{OK} Mininet instalado: {version}')


def check_ovs():
    """Verifica que Open vSwitch esté activo y lo inicia si no lo está."""
    result = subprocess.run(
        ['systemctl', 'is-active', 'openvswitch-switch'],
        capture_output=True, text=True
    )
    if result.stdout.strip() != 'active':
        print(f'{WARN} Open vSwitch no está activo. Iniciando...')
        subprocess.run(['systemctl', 'start', 'openvswitch-switch'])
        time.sleep(2)
        # Verificar de nuevo
        result2 = subprocess.run(
            ['systemctl', 'is-active', 'openvswitch-switch'],
            capture_output=True, text=True
        )
        if result2.stdout.strip() != 'active':
            print(f'{ERROR} No se pudo iniciar Open vSwitch.')
            print('        Intenta manualmente: sudo systemctl start openvswitch-switch\n')
            sys.exit(1)
    print(f'{OK} Open vSwitch activo')


def check_python_deps():
    """Verifica que los módulos de Python necesarios estén disponibles."""
    deps = {
        'mininet.net':     'mininet',
        'mininet.node':    'mininet',
        'mininet.cli':     'mininet',
        'mininet.link':    'mininet',
        'requests':        'requests',
    }
    faltantes = []
    for modulo, paquete in deps.items():
        try:
            __import__(modulo)
        except ImportError:
            faltantes.append(paquete)

    if faltantes:
        paquetes_unicos = list(set(faltantes))
        print(f'{ERROR} Faltan dependencias Python:')
        for p in paquetes_unicos:
            print(f'        pip install {p}')
        sys.exit(1)
    print(f'{OK} Dependencias Python disponibles (mininet, requests)')


def check_topology_file():
    """Verifica que el archivo de topología exista en el directorio actual."""
    if not os.path.isfile(TOPOLOGY_SCRIPT):
        print(f'{ERROR} No se encontró {TOPOLOGY_SCRIPT} en el directorio actual.')
        print(f'        Asegúrate de correr este script desde la misma carpeta')
        print(f'        donde está {TOPOLOGY_SCRIPT}\n')
        sys.exit(1)
    print(f'{OK} Archivo de topología encontrado: {TOPOLOGY_SCRIPT}')


def check_ryu_controller():
    """
    Verifica que el controlador Ryu esté escuchando en CONTROLLER_PORT.
    Intenta una conexión TCP real — si el puerto responde, Ryu está listo.
    """
    intentos = 3
    for i in range(intentos):
        try:
            s = socket.create_connection(
                (CONTROLLER_IP, CONTROLLER_PORT), timeout=2
            )
            s.close()
            print(f'{OK} Controlador Ryu detectado en {CONTROLLER_IP}:{CONTROLLER_PORT}')
            return
        except (ConnectionRefusedError, socket.timeout, OSError):
            if i < intentos - 1:
                print(f'{WARN} Intento {i+1}/{intentos}: Ryu no responde en puerto {CONTROLLER_PORT}. Reintentando...')
                time.sleep(2)

    # Si llegó aquí, Ryu no está corriendo
    print(f'\n{ERROR} El controlador Ryu NO está escuchando en el puerto {CONTROLLER_PORT}.')
    print()
    print('  ─── SOLUCIÓN ─────────────────────────────────────────')
    print('  Abre OTRA terminal y ejecuta:')
    print()
    print('      ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633')
    print()
    print('  Espera hasta ver el mensaje:')
    print('      "Controlador SDN iniciado — esperando conexión de switches..."')
    print()
    print('  Luego vuelve a correr este script.')
    print('  ─────────────────────────────────────────────────────')
    print()
    sys.exit(1)


def check_port_free():
    """
    Verifica que no haya instancias previas de Mininet corriendo
    que puedan generar conflicto de interfaces.
    """
    result = subprocess.run(
        ['pgrep', '-f', 'mininet'],
        capture_output=True, text=True
    )
    if result.stdout.strip():
        print(f'{WARN} Hay procesos de Mininet activos (PIDs: {result.stdout.strip().replace(chr(10), ", ")})')
        print(f'       Se ejecutará limpieza antes de continuar.')
    else:
        print(f'{OK} Sin instancias previas de Mininet')


# ═══════════════════════════════════════════════════════════════════════════════
# LIMPIEZA
# ═══════════════════════════════════════════════════════════════════════════════

def clean_previous():
    """
    Limpia residuos de sesiones anteriores de Mininet.
    Esto elimina namespaces de red huérfanos, bridges OVS y veth pairs
    que quedan si el script anterior terminó de forma abrupta.
    """
    print(f'{INFO} Ejecutando mn --clean ...')
    subprocess.run(
        ['mn', '--clean'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # También limpiar bridges OVS huérfanos
    result = subprocess.run(
        ['ovs-vsctl', 'list-br'],
        capture_output=True, text=True
    )
    bridges = result.stdout.strip().split('\n')
    for br in bridges:
        if br and br.startswith('s'):
            subprocess.run(
                ['ovs-vsctl', 'del-br', br],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    print(f'{OK} Limpieza completada')


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print()
    print(SEP)
    print('  ARRANQUE DE TOPOLOGÍA SDN — PROYECTO DE GRADO')
    print('  Universidad Católica de Colombia — 2026')
    print(SEP)

    # ── Verificaciones ────────────────────────────────────────────────────────
    titulo('PASO 1 — VERIFICACIONES PREVIAS')
    check_root()
    check_mininet()
    check_ovs()
    check_python_deps()
    check_topology_file()
    check_port_free()
    check_ryu_controller()

    # ── Limpieza ──────────────────────────────────────────────────────────────
    titulo('PASO 2 — LIMPIEZA DE SESIONES ANTERIORES')
    clean_previous()

    # ── Arranque ──────────────────────────────────────────────────────────────
    titulo('PASO 3 — INICIANDO TOPOLOGÍA')
    print(f'{INFO} Cargando {TOPOLOGY_SCRIPT}...\n')
    time.sleep(1)

    # Importar y ejecutar la topología directamente en el mismo proceso
    # para mantener el mismo proceso raíz (necesario para Mininet con sudo)
    import importlib.util
    spec = importlib.util.spec_from_file_location('topology', TOPOLOGY_SCRIPT)
    topo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(topo)
    topo.run()


if __name__ == '__main__':
    main()
