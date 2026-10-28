#!/usr/bin/env python3
"""
=============================================================================
EVALUACIÓN COMPLETA DEL OBJETIVO 3 — CONTROLADOR + AGENTE (un solo comando)
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Prueba el controlador Ryu y el agente al mismo tiempo, con tráfico y
ataques reales en Mininet, y termina con el resumen estadístico.

  0. Verificaciones previas y plan de acción (plan_de_accion.md).
  1. Agente: usa el que esté en :8081 o lo arranca desde su carpeta con su
     .env (tokens incluidos). Pone CONTEXTO_HABILITADO=false para que las
     corridas sean independientes.
  2. Serie "llm": LLM_HABILITADO=true y orquestador.py con todos los
     escenarios (Ryu y Mininet nuevos en cada corrida).
  3. Serie "reglas": LLM_HABILITADO=false (respaldo por reglas) y la misma
     serie, para comparar el LLM con las reglas con el mismo detector.
  4. Espera a que el agente termine de explicar, restaura su configuración
     y genera el informe conjunto (informe/resumen.md) y la planilla de
     calificación humana a ciegas (calificacion/).

El agente nunca desbloquea ni aplica acciones: nadie aprueba nada durante
la evaluación, así que todo host aislado sigue en DROP hasta que Ryu se
reinicia en la corrida siguiente.

USO:
  python3 evaluacion/correr_evaluacion.py --dry-run          # verificaciones y plan, sin sudo
  sudo /usr/bin/python3 evaluacion/correr_evaluacion.py --solo A6,B1 --repeticiones 1   # humo
  sudo /usr/bin/python3 evaluacion/correr_evaluacion.py      # evaluación completa
=============================================================================
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

DIR_EVAL = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DIR_EVAL)

import evaluar       # noqa: E402
import orquestador   # noqa: E402

AGENTE = 'http://127.0.0.1:8081'
BLOQUES = {'llm': True, 'reglas': False}   # bloque → LLM_HABILITADO


def log(msg):
    orquestador.log(msg)


def usuario():
    return os.environ.get('SUDO_USER') or os.environ.get('USER') or ''


def leer_env(ruta):
    valores = {}
    with open(ruta, encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith('#') and '=' in linea:
                clave, valor = linea.split('=', 1)
                valores[clave.strip()] = valor.strip().strip('"').strip("'")
    return valores


# ─── Agente ──────────────────────────────────────────────────────────────────

def pedir(metodo, ruta, token, cuerpo=None, timeout=10):
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(AGENTE + ruta, data=datos, method=metodo,
                                 headers={'X-Operador-Token': token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def arrancar_agente(dir_agente, log_path):
    """uvicorn como el usuario que llamó a sudo, con un entorno limpio para que mande su .env."""
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL') if k in os.environ}
    env['HOME'] = os.path.expanduser(f'~{usuario()}')
    extra = {'user': usuario()} if os.geteuid() == 0 and usuario() else {}
    salida = open(log_path, 'w')
    proc = subprocess.Popen([os.path.join(dir_agente, '.venv', 'bin', 'uvicorn'), 'app.main:app', '--port', '8081'],
                            cwd=dir_agente, stdout=salida, stderr=subprocess.STDOUT, env=env, **extra)
    if not orquestador.esperar(orquestador.agente_disponible, 30):
        orquestador.detener(proc)
        raise SystemExit(f'El agente no arrancó en 30 s; revisa {log_path}')
    return proc, salida


def esperar_explicaciones(token, desde, timeout):
    """Espera a que todo incidente recibido desde `desde` tenga t_explicado (el LLM tarda hasta LLM_TIMEOUT)."""
    limite = time.time() + timeout
    while time.time() < limite:
        try:
            pendientes = [i for i in pedir('GET', '/api/incidentes?origen=real&limite=200', token)
                          if evaluar.fecha(i.get('t_recibido')) and evaluar.fecha(i['t_recibido']) >= desde
                          and not i.get('t_explicado')]
        except Exception:
            pendientes = []
        if not pendientes:
            return
        time.sleep(3)
    log(f'  aviso: quedaron incidentes sin explicar tras {timeout} s')


# ─── Verificaciones y plan de acción ─────────────────────────────────────────

def verificaciones(dir_agente):
    repo = orquestador.REPO
    filas = [
        ('Ryu instalado en RYU_IA/.venv', os.path.exists(os.path.join(repo, '.venv', 'bin', 'ryu-manager'))),
        ('Mininet importable (python3 del sistema)',
         subprocess.call([sys.executable, '-c', 'import mininet'], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL) == 0),
        ('Puertos 6633 y 8080 libres (sin Ryu ni mock de Ryu corriendo)',
         not any(orquestador.puerto_ocupado(p) for p in (6633, 8080))),
        (f'Agente en {dir_agente}', os.path.exists(os.path.join(dir_agente, 'app', 'main.py'))),
        ('.env del agente', os.path.exists(os.path.join(dir_agente, '.env'))),
        ('Agente ya corriendo en :8081 (si no, se arranca)', orquestador.agente_disponible()),
    ]
    tokens = {}
    if filas[4][1]:
        env = leer_env(os.path.join(dir_agente, '.env'))
        tokens = {k: env.get(k, '') for k in ('AGENT_TOKEN', 'OPERADOR_TOKEN')}
        filas.append(('AGENT_TOKEN y OPERADOR_TOKEN en el .env', all(tokens.values())))
        filas.append(('APPSCRIPT_URL en el .env (sin ella no se mide la notificación)', bool(env.get('APPSCRIPT_URL'))))
    return filas, tokens


def duracion_estimada(escenarios, repeticiones, n_bloques):
    """Segundos aproximados: arranque + gracia + escenario + cierre."""
    por_ronda = 0
    for e in escenarios:
        bloquea = e['etiqueta'] == 'ataque' and not e.get('dificil')
        por_ronda += 15 + 35 + (40 if bloquea else e['duracion_max_s'] + 15) + 15 + 5
    return por_ronda * repeticiones * n_bloques


def plan_de_accion(args, escenarios, filas, n_bloques):
    horas = duracion_estimada(escenarios, args.repeticiones, n_bloques) / 3600
    obligatorias = [f for f in filas if not f[0].startswith(('Agente ya', 'APPSCRIPT'))]
    lineas = [
        '# Plan de acción — evaluación del objetivo 3', '',
        f'Fecha: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}', '',
        '## Verificaciones previas', '',
        *[f'- [{"x" if ok else " "}] {nombre}' for nombre, ok in filas], '',
        '## Qué se va a ejecutar', '',
        f'- Escenarios: {", ".join(e["id"] for e in escenarios)} '
        f'({sum(e["etiqueta"] == "ataque" for e in escenarios)} de ataque, '
        f'{sum(e["etiqueta"] == "benigno" for e in escenarios)} benignos).',
        f'- Repeticiones: {args.repeticiones} por escenario, en orden aleatorio (semilla {args.semilla}).',
        f'- Series: {", ".join(args.bloques)} (llm = LLM activo; reglas = LLM apagado, respaldo por reglas).',
        f'- Corridas: {len(escenarios) * args.repeticiones * n_bloques}; duración estimada: {horas:.1f} h.',
        f'- Peticiones al LLM: hasta {len(escenarios) * args.repeticiones if "llm" in args.bloques else 0} '
        '(cupo diario 1.000).',
        '- Correos: uno por incidente detectado, si APPSCRIPT_URL está configurada.', '',
        '## Pasos', '',
        '1. Verificaciones previas (arriba). Si alguna obligatoria falla, el script se detiene.',
        '2. Agente: se usa el que esté en :8081 o se arranca con su .env; CONTEXTO_HABILITADO=false.',
        '3. Por cada serie: se fija LLM_HABILITADO y se corren todos los escenarios. En cada corrida: Ryu y '
        'Mininet nuevos, calentamiento, víctimas, escenario, bloqueo, alerta al agente, explicación, DROP en '
        's1, s2 y s3.',
        '4. Se espera a que el agente termine de explicar y se restaura su configuración.',
        '5. Informe conjunto: informe/resumen.md (cumplimiento del objetivo 3, detección, contención, tiempos, '
        'explicación, recomendación y LLM frente a reglas), corridas.csv y evaluacion.json.',
        '6. Planilla de calificación humana a ciegas en calificacion/: cada evaluador la llena por separado y '
        'luego se corre `evaluar.py calificaciones` (alfa de Krippendorff).', '',
        '## Si algo falla', '',
        '- Una corrida con error queda en el manifiesto con su motivo y no cuenta en las métricas.',
        '- Si el script se interrumpe, las series ya corridas quedan en su carpeta; el informe se repite con '
        '`python3 evaluacion/evaluar.py metricas <manifiestos...> --salida <carpeta>` (con OPERADOR_TOKEN exportado).',
        '- Al terminar o interrumpir, se restaura la configuración del agente y se apaga si lo arrancó el script.',
    ]
    return '\n'.join(lineas) + '\n', all(ok for _, ok in obligatorias), horas


# ─── Principal ───────────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--agente-dir', default=None,
                        help='carpeta de sdn-agent-v2 (por defecto ~/Desktop/sdn-agent-v2 del usuario)')
    parser.add_argument('--solo', help='ids separados por coma, p. ej. A6,B1')
    parser.add_argument('--repeticiones', type=int, default=10)
    parser.add_argument('--semilla', type=int, default=20261028)
    parser.add_argument('--bloques', default='llm,reglas', help='series a correr: llm, reglas o ambas')
    parser.add_argument('--salida', default=os.path.join(DIR_EVAL, 'resultados'))
    parser.add_argument('--espera-explicaciones', type=float, default=240)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    args.bloques = [b.strip() for b in args.bloques.split(',') if b.strip()]
    if not args.bloques or set(args.bloques) - set(BLOQUES):
        raise SystemExit(f'--bloques admite: {", ".join(BLOQUES)}')
    dir_agente = args.agente_dir or os.path.expanduser(f'~{usuario()}/Desktop/sdn-agent-v2')

    escenarios = orquestador.cargar_escenarios(os.path.join(DIR_EVAL, 'escenarios_r4.json'), args.solo)
    filas, tokens = verificaciones(dir_agente)
    texto_plan, listo, horas = plan_de_accion(args, escenarios, filas, len(args.bloques))
    print(texto_plan)
    if args.dry_run:
        return 0
    if not listo:
        raise SystemExit('Hay verificaciones obligatorias sin cumplir (ver arriba).')
    if os.geteuid() != 0:
        raise SystemExit('Mininet necesita root: sudo /usr/bin/python3 evaluacion/correr_evaluacion.py')

    base = os.path.join(args.salida, datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_objetivo3')
    os.makedirs(base, exist_ok=True)
    with open(os.path.join(base, 'plan_de_accion.md'), 'w', encoding='utf-8') as f:
        f.write(texto_plan)
    os.environ.update(AGENT_TOKEN=tokens['AGENT_TOKEN'], OPERADOR_TOKEN=tokens['OPERADOR_TOKEN'],
                      AGENTE_URL=AGENTE)
    token = tokens['OPERADOR_TOKEN']

    agente, agente_salida = None, None
    if not orquestador.agente_disponible():
        log('Arrancando el agente')
        agente, agente_salida = arrancar_agente(dir_agente, os.path.join(base, 'agente.log'))
    original = pedir('GET', '/api/config', token)
    manifiestos = []
    try:
        pedir('PUT', '/api/config', token, {'CONTEXTO_HABILITADO': False})
        for bloque in args.bloques:
            pedir('PUT', '/api/config', token, {'LLM_HABILITADO': BLOQUES[bloque]})
            log(f'=== Serie {bloque} (LLM_HABILITADO={BLOQUES[bloque]}) ===')
            desde = datetime.now(timezone.utc).replace(tzinfo=None)
            manifiesto = orquestador.ejecutar(['--repeticiones', str(args.repeticiones), '--semilla', str(args.semilla),
                                               '--bloque', bloque, '--salida', base, '--sin-informe']
                                              + (['--solo', args.solo] if args.solo else []))
            manifiestos.append(manifiesto)
            log('  esperando a que el agente termine de explicar')
            esperar_explicaciones(token, desde, args.espera_explicaciones)
    finally:
        try:
            pedir('PUT', '/api/config', token, {k: original[k] for k in ('LLM_HABILITADO', 'CONTEXTO_HABILITADO')})
        except Exception as e:
            log(f'AVISO: no se pudo restaurar la configuración del agente ({e}); revísala en el panel')

    log('Generando el informe conjunto')
    informe = os.path.join(base, 'informe')
    try:
        evaluar.main(['metricas', *manifiestos, '--salida', informe])
        evaluar.main(['plantilla', *manifiestos, '--salida', os.path.join(base, 'calificacion')])
    finally:
        if agente is not None:
            orquestador.detener(agente)
            agente_salida.close()
        if os.environ.get('SUDO_UID'):
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            for raiz, _, archivos in os.walk(base):
                for nombre in [raiz] + [os.path.join(raiz, a) for a in archivos]:
                    os.chown(nombre, uid, gid)
    log(f'Listo. Informe: {os.path.join(informe, "resumen.md")}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
