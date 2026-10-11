#!/usr/bin/env python3
"""
=============================================================================
SERVIDOR JSON — RECEPTOR DE ALERTAS RYU
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

USO:
    python3 servidor_json.py

Levanta un servidor HTTP en el puerto 8081 que recibe el payload JSON
que envía el controlador Ryu cuando detecta un incidente CRÍTICO.
Imprime el JSON formateado en consola para verificar que llega correctamente.

No requiere ninguna dependencia externa — solo Python estándar.
=============================================================================
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

PORT = 8081

BOLD   = '\033[1m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RED    = '\033[91m'
BLUE   = '\033[94m'
RESET  = '\033[0m'

def ts():
    return datetime.now().strftime('%H:%M:%S')


class AlertHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # Leer el body
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length)

        print(f'\n{BOLD}{"="*60}{RESET}')
        print(f'{BOLD}  ALERTA RECIBIDA — {ts()}{RESET}')
        print(f'{BOLD}{"="*60}{RESET}')
        print(f'  Ruta   : {self.path}')
        print(f'  Método : POST')
        print(f'  Bytes  : {length}')
        print()

        # Intentar parsear como JSON
        try:
            data = json.loads(body)
            print(f'{GREEN}  JSON válido ✓{RESET}')
            print()
            print(f'{BOLD}  PAYLOAD:{RESET}')
            print(json.dumps(data, indent=4, ensure_ascii=False))
        except json.JSONDecodeError as e:
            print(f'{RED}  JSON inválido: {e}{RESET}')
            print(f'  Body raw: {body.decode("utf-8", errors="replace")}')

        print(f'\n{BOLD}{"="*60}{RESET}\n')

        # Responder 200 OK a Ryu
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_GET(self):
        """Health check — para verificar que el servidor está vivo."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "ok", "servidor": "receptor-json-ryu"}')

    def log_message(self, format, *args):
        """Silencia el log por defecto de BaseHTTPRequestHandler."""
        pass   # los prints ya los manejamos arriba


def main():
    print()
    print(f'{BOLD}{"="*60}{RESET}')
    print(f'{BOLD}  SERVIDOR JSON — RECEPTOR DE ALERTAS RYU{RESET}')
    print(f'{BOLD}  Universidad Católica de Colombia — 2026{RESET}')
    print(f'{BOLD}{"="*60}{RESET}')
    print(f'  Escuchando en: http://0.0.0.0:{PORT}')
    print(f'  Endpoint     : POST http://localhost:{PORT}/alert')
    print(f'  Health check : GET  http://localhost:{PORT}/')
    print(f'  Ctrl+C para detener')
    print(f'{BOLD}{"="*60}{RESET}')
    print(f'\n{YELLOW}  Esperando alertas del controlador Ryu...{RESET}\n')

    server = HTTPServer(('0.0.0.0', PORT), AlertHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f'\n{YELLOW}  Servidor detenido.{RESET}')
        sys.exit(0)


if __name__ == '__main__':
    main()
