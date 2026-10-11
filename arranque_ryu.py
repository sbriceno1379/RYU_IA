#!/usr/bin/env python3
"""
=============================================================================
ARRANQUE DEL CONTROLADOR RYU — PROYECTO DE GRADO
Universidad Católica de Colombia — 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

USO:
    python3 arranque_ryu.py

Ejecutar ANTES de run_mininet.py en una terminal aparte.
=============================================================================
"""

import os
import sys
import subprocess
import socket
import time

CONTROLLER_FILE = 'ryu_controller.py'
CONTROLLER_PORT = 6633

OK    = '\033[92m[OK]   \033[0m'
WARN  = '\033[93m[WARN] \033[0m'
ERROR = '\033[91m[ERROR]\033[0m'
INFO  = '\033[94m[INFO] \033[0m'
SEP   = '=' * 60


def check_ryu_manager():
    """Verifica que ryu-manager esté instalado."""
    result = subprocess.run(['which', 'ryu-manager'], capture_output=True, text=True)
    if result.returncode != 0:
        print(f'{ERROR} ryu-manager no encontrado.')
        print('        Instalar con:  pip install ryu')
        sys.exit(1)
    print(f'{OK} ryu-manager encontrado: {result.stdout.strip()}')


def check_controller_file():
    """Verifica que ryu_controller.py exista en el directorio actual."""
    if not os.path.isfile(CONTROLLER_FILE):
        print(f'{ERROR} No se encontró {CONTROLLER_FILE} en el directorio actual.')
        print(f'        Asegúrate de correr este script desde la misma carpeta.')
        sys.exit(1)
    print(f'{OK} Controlador encontrado: {CONTROLLER_FILE}')


def check_port_free():
    """Si el puerto 6633 ya está ocupado, ofrece matar el proceso anterior."""
    try:
        s = socket.create_connection(('127.0.0.1', CONTROLLER_PORT), timeout=1)
        s.close()
        # Si llegó aquí, el puerto está ocupado
        print(f'{WARN} Puerto {CONTROLLER_PORT} ya está en uso.')
        resp = input('        ¿Matar el proceso anterior y continuar? [s/N]: ').strip().lower()
        if resp == 's':
            subprocess.run(['pkill', '-f', 'ryu-manager'], capture_output=True)
            time.sleep(2)
            print(f'{OK} Proceso anterior terminado.')
        else:
            print('        Cancelado.')
            sys.exit(0)
    except (ConnectionRefusedError, socket.timeout, OSError):
        print(f'{OK} Puerto {CONTROLLER_PORT} libre')


def launch_ryu():
    """Lanza ryu-manager en primer plano (log visible en esta terminal)."""
    print()
    print(SEP)
    print('  Iniciando Ryu en puerto 6633...')
    print(SEP)
    print(f'{INFO} Espera el mensaje:')
    print('       "Controlador SDN iniciado — esperando conexión de switches..."')
    print(f'{INFO} Luego abre OTRA terminal y ejecuta:')
    print('       sudo python3 run_mininet.py')
    print(SEP)
    print()

    os.execvp('ryu-manager', [
        'ryu-manager',
        CONTROLLER_FILE,
        '--ofp-tcp-listen-port', str(CONTROLLER_PORT),
    ])
    # os.execvp reemplaza el proceso actual — nunca llega aquí


def main():
    print()
    print(SEP)
    print('  CONTROLADOR RYU — SDN PROYECTO DE GRADO')
    print('  Universidad Católica de Colombia — 2026')
    print(SEP)

    check_ryu_manager()
    check_controller_file()
    check_port_free()
    launch_ryu()


if __name__ == '__main__':
    main()
