#!/usr/bin/env python3
"""
=============================================================================
INICIAR VÍCTIMAS — PROYECTO DE GRADO
Universidad Católica de Colombia — 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

USO:
    python3 iniciar_victimas.py | bash

    Esto genera y ejecuta automáticamente los comandos para levantar
    los servidores TCP en h2..h10 usando mnexec (ejecuta comandos
    dentro del namespace de red de cada host Mininet).

    O simplemente copia y pega la salida en la CLI de Mininet.

REQUISITO:
    Mininet debe estar corriendo (sudo python3 run_mininet.py activo).
=============================================================================
"""

import subprocess
import sys
import os
import time
from datetime import datetime

HOSTS_VICTIMAS  = list(range(2, 11))    # h2..h10
SCRIPT          = 'ataque_completo.py'
DIR_SCRIPT      = os.path.expanduser('~/Downloads/RYU_IA')

GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def ts():
    return datetime.now().strftime('%H:%M:%S')

def get_host_pid(host_name):
    """
    Obtiene el PID del proceso del host en Mininet buscando
    el namespace de red con el nombre del host.
    """
    try:
        result = subprocess.run(
            ['grep', '-r', host_name, '/var/run/netns/'],
            capture_output=True, text=True
        )
        # Alternativa: buscar por nombre en /proc
        result2 = subprocess.run(
            ['pgrep', '-f', f'mininet:{host_name}'],
            capture_output=True, text=True
        )
        if result2.stdout.strip():
            return result2.stdout.strip().split('\n')[0]
    except Exception:
        pass
    return None


def lanzar_con_mnexec(host_num):
    """Lanza el script en el namespace del host usando mnexec."""
    host_name = f'h{host_num}'
    pid = get_host_pid(host_name)

    if not pid:
        print(f'{RED}[ERROR]{RESET} No se encontró PID para {host_name}')
        print(f'        ¿Está Mininet corriendo?')
        return False

    script_path = os.path.join(DIR_SCRIPT, SCRIPT)
    cmd = ['mnexec', '-a', pid, 'python3', script_path]

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f'{GREEN}[OK]{RESET}    {host_name} (PID={pid}) → servidor iniciado')
        return True
    except FileNotFoundError:
        print(f'{RED}[ERROR]{RESET} mnexec no encontrado')
        return False
    except Exception as e:
        print(f'{RED}[ERROR]{RESET} {host_name}: {e}')
        return False


def main():
    print(f'\n{BOLD}{"="*55}{RESET}')
    print(f'{BOLD}  INICIANDO SERVIDORES TCP EN VÍCTIMAS{RESET}')
    print(f'{BOLD}  Universidad Católica de Colombia — 2026{RESET}')
    print(f'{BOLD}{"="*55}{RESET}')
    print(f'  Hosts   : h{HOSTS_VICTIMAS[0]}..h{HOSTS_VICTIMAS[-1]}')
    print(f'  Script  : {SCRIPT}')
    print(f'  Directorio: {DIR_SCRIPT}')
    print(f'{"="*55}\n')

    if os.geteuid() != 0:
        print(f'{RED}[ERROR]{RESET} Este script requiere sudo:')
        print(f'        sudo python3 iniciar_victimas.py')
        sys.exit(1)

    exitosos = 0
    for host_num in HOSTS_VICTIMAS:
        if lanzar_con_mnexec(host_num):
            exitosos += 1
        time.sleep(0.3)

    print(f'\n{"="*55}')
    if exitosos == len(HOSTS_VICTIMAS):
        print(f'{GREEN}{BOLD}  {exitosos}/{len(HOSTS_VICTIMAS)} servidores iniciados correctamente ✓{RESET}')
        print(f'\n  Espera 3 segundos y luego ejecuta en Mininet:')
        print(f'  {BOLD}mininet> h1 python3 {SCRIPT}{RESET}')
    else:
        print(f'{YELLOW}  {exitosos}/{len(HOSTS_VICTIMAS)} servidores iniciados{RESET}')
        print(f'\n  Para los que fallaron, usa la CLI de Mininet manualmente:')
        for i in HOSTS_VICTIMAS:
            print(f'    mininet> h{i} python3 {SCRIPT} &')
    print(f'{"="*55}\n')


if __name__ == '__main__':
    main()
