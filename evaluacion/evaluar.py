#!/usr/bin/env python3
"""
=============================================================================
EVALUADOR (R4 / objetivo 3)
Universidad Católica de Colombia — Proyecto de Grado 2026
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Lee uno o más manifiesto.jsonl de orquestador.py, cruza cada corrida con su
incidente en el agente (GET /api/incidentes, con X-Operador-Token) y calcula
las métricas del objetivo 3. No necesita sudo ni dependencias.

  Detección (Ryu, por corrida):  matriz de confusión, precisión, exhaustividad
      (recall), especificidad, tasas de FP y FN, F1, exactitud y MCC, con
      intervalos de Wilson al 95 %.
  Contención: DROP presente en los 3 switches, conexiones del atacante
      aceptadas después del bloqueo y equipos alcanzados antes del bloqueo.
  Tiempos: detección (t_inicio → bloqueo), entrega de la alerta, explicación,
      notificación, total hasta el operador y desbloqueo (si lo hubo), con
      media, desviación, mediana, p25, p75, p95, mínimo y máximo.
  Explicación (agente): concordancia del veredicto con la etiqueta, tasa de
      abstención (indeterminado), fuente (LLM o reglas), verificación numérica,
      cobertura de las métricas disparadas y bloques reemplazados por plantilla.
  Recomendación: acción recomendada frente a las aceptables del escenario y
      recomendaciones inseguras (relajar la contención en un ataque).

Subcomandos:
  evaluar.py metricas  MANIFIESTO [MANIFIESTO ...] [--salida DIR] [--sin-agente]
  evaluar.py plantilla MANIFIESTO [...] --salida DIR      (calificación humana a ciegas)
  evaluar.py calificaciones --clave clave.csv eval1.csv eval2.csv [...]

Variables: OPERADOR_TOKEN (la del .env del agente), AGENTE_URL (por defecto
http://127.0.0.1:8081).
=============================================================================
"""

import argparse
import csv
import json
import math
import os
import random
import re
import statistics
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta

Z95 = 1.959963984540054
METRICAS = ('M1', 'M2', 'M3', 'M4', 'M5')

# Acciones de la escalera (C7) que se aceptan como recomendación en cada clase.
# En un ataque, limitar_tasa devuelve la red al host: es la única insegura.
ACEPTABLES = {
    'ataque': {'preferidas': {'cuarentena_puertos', 'cuarentena_vlan'},
               'aceptables': {'cuarentena_puertos', 'cuarentena_vlan', 'mantener_drop'},
               'inseguras': {'limitar_tasa'}},
    'benigno': {'preferidas': {'limitar_tasa'},
                'aceptables': {'limitar_tasa', 'mantener_drop'},
                'inseguras': set()},
}
VEREDICTO_ESPERADO = {'ataque': 'confirmado', 'benigno': 'falso_positivo'}

# Cómo puede aparecer cada métrica en el texto de la explicación (heurística declarada).
PATRONES_METRICA = {
    'M1': r'\bM1\b|nuevos? flujos|flujos nuevos|conexiones nuevas|tasa de (nuevas )?conexiones',
    'M2': r'\bM2\b|destinos? (únicos|unicos|distintos)|fan-?out',
    'M3': r'\bM3\b|\bSMB\b.*(breve|volum|bytes)|transferencia (smb|breve)',
    'M4': r'\bM4\b|packet-?in',
    'M5': r'\bM5\b|east-?west|este-?oeste|entre (equipos|estaciones)',
}

# '[M1] 10.0.10.1 — M1: ... | peso=25 | puntaje=25 | ...' (la hora delante depende del formato de ryu-manager)
RE_METRICA_RYU = re.compile(r'\[(?P<m>M\d)\] (?P<ip>\d+\.\d+\.\d+\.\d+) — .*\| puntaje=(?P<p>\d+)')


# ═════════════════════════════════════════════════════════════════════════════
#  Utilidades
# ═════════════════════════════════════════════════════════════════════════════

def fecha(texto):
    """ISO-8601 (con Z o con zona) → datetime sin zona en UTC. None si no hay."""
    if not texto:
        return None
    dt = datetime.fromisoformat(texto.replace('Z', '+00:00'))
    if dt.tzinfo is not None:
        dt = (dt - dt.utcoffset()).replace(tzinfo=None)
    return dt


def segundos(a, b):
    """b − a en segundos, o None."""
    if a is None or b is None:
        return None
    return round((b - a).total_seconds(), 3)


def wilson(exitos, n):
    """Intervalo de Wilson al 95 % para una proporción (Brown, Cai y DasGupta, 2001)."""
    if n == 0:
        return {'valor': None, 'ic95': [None, None], 'k': exitos, 'n': n}
    p = exitos / n
    den = 1 + Z95 ** 2 / n
    centro = (p + Z95 ** 2 / (2 * n)) / den
    margen = Z95 * math.sqrt(p * (1 - p) / n + Z95 ** 2 / (4 * n ** 2)) / den
    return {'valor': round(p, 4), 'ic95': [round(max(0.0, centro - margen), 4), round(min(1.0, centro + margen), 4)],
            'k': exitos, 'n': n}


def percentil(valores, q):
    """Percentil con interpolación lineal (igual que numpy por defecto)."""
    v = sorted(valores)
    if not v:
        return None
    pos = (len(v) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return v[lo] + (v[hi] - v[lo]) * (pos - lo)


def describir(valores):
    v = [x for x in valores if x is not None]
    if not v:
        return {'n': 0}
    r = lambda x: None if x is None else round(x, 3)
    return {'n': len(v), 'media': r(statistics.mean(v)), 'de': r(statistics.stdev(v)) if len(v) > 1 else None,
            'mediana': r(statistics.median(v)), 'p25': r(percentil(v, 0.25)), 'p75': r(percentil(v, 0.75)),
            'p95': r(percentil(v, 0.95)), 'min': r(min(v)), 'max': r(max(v))}


def fisher_exacto(a, b, c, d):
    """p bilateral de la prueba exacta de Fisher para la tabla [[a, b], [c, d]] (suma de las tablas
    con probabilidad hipergeométrica menor o igual que la observada)."""
    fila1, col1, n = a + b, a + c, a + b + c + d
    if n == 0:
        return None

    def prob(x):
        return math.comb(col1, x) * math.comb(n - col1, fila1 - x) / math.comb(n, fila1)

    observada = prob(a)
    p = sum(prob(x) for x in range(max(0, fila1 + col1 - n), min(fila1, col1) + 1)
            if prob(x) <= observada * (1 + 1e-9))
    return round(min(1.0, p), 4)


def mann_whitney(x, y):
    """U de Mann-Whitney con aproximación normal, corrección por empates y de continuidad (p bilateral),
    y delta de Cliff como tamaño del efecto (positivo: x tiende a ser mayor)."""
    x, y = [v for v in x if v is not None], [v for v in y if v is not None]
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return {'n1': n1, 'n2': n2, 'U': None, 'p': None, 'delta_cliff': None}
    todos = sorted((v, g) for g, vs in ((0, x), (1, y)) for v in vs)
    rangos, i = {}, 0
    empates = 0.0
    while i < len(todos):
        j = i
        while j + 1 < len(todos) and todos[j + 1][0] == todos[i][0]:
            j += 1
        t = j - i + 1
        empates += t ** 3 - t
        for k in range(i, j + 1):
            rangos[k] = (i + j) / 2 + 1
        i = j + 1
    r1 = sum(rangos[k] for k, (_, g) in enumerate(todos) if g == 0)
    u1 = r1 - n1 * (n1 + 1) / 2
    n = n1 + n2
    var = n1 * n2 / 12 * ((n + 1) - empates / (n * (n - 1))) if n > 1 else 0
    if var <= 0:
        p = 1.0
    else:
        z = (abs(u1 - n1 * n2 / 2) - 0.5) / math.sqrt(var)
        p = math.erfc(max(z, 0) / math.sqrt(2))
    delta = (2 * u1 / (n1 * n2)) - 1
    return {'n1': n1, 'n2': n2, 'U': round(u1, 1), 'p': round(min(1.0, p), 4), 'delta_cliff': round(delta, 4)}


def comparar_bloques(filas, a='llm', b='reglas'):
    """Serie con LLM frente a serie con respaldo por reglas (mismo detector, mismos escenarios)."""
    fa = [f for f in filas if f.get('bloque') == a and f.get('incidente_id') and not f.get('error')]
    fb = [f for f in filas if f.get('bloque') == b and f.get('incidente_id') and not f.get('error')]
    if not fa or not fb:
        return None

    def tabla(campo, filtro=lambda f: True):
        ga = [f[campo] for f in fa if filtro(f) and f.get(campo) is not None]
        gb = [f[campo] for f in fb if filtro(f) and f.get(campo) is not None]
        k1, k2 = sum(1 for v in ga if v), sum(1 for v in gb if v)
        return {a: wilson(k1, len(ga)), b: wilson(k2, len(gb)),
                'p_fisher': fisher_exacto(k1, len(ga) - k1, k2, len(gb) - k2)}

    return {
        'concordancia_veredicto': tabla('veredicto_correcto', lambda f: not f.get('abstencion')),
        'abstencion': tabla('abstencion'),
        'accion_preferida': tabla('accion_preferida'),
        'accion_insegura': tabla('accion_insegura'),
        't_explicacion_s': mann_whitney([f.get('t_explicacion_s') for f in fa], [f.get('t_explicacion_s') for f in fb]),
        't_total_hasta_operador_s': mann_whitney([f.get('t_total_hasta_operador_s') for f in fa],
                                                 [f.get('t_total_hasta_operador_s') for f in fb]),
    }


def confusion(filas):
    vp = sum(1 for f in filas if f['etiqueta'] == 'ataque' and f['detectado'])
    fn = sum(1 for f in filas if f['etiqueta'] == 'ataque' and not f['detectado'])
    fp = sum(1 for f in filas if f['etiqueta'] == 'benigno' and f['detectado'])
    vn = sum(1 for f in filas if f['etiqueta'] == 'benigno' and not f['detectado'])
    precision = wilson(vp, vp + fp)
    recall = wilson(vp, vp + fn)
    f1 = None
    if precision['valor'] is not None and recall['valor'] is not None and precision['valor'] + recall['valor'] > 0:
        f1 = round(2 * precision['valor'] * recall['valor'] / (precision['valor'] + recall['valor']), 4)
    den = math.sqrt((vp + fp) * (vp + fn) * (vn + fp) * (vn + fn))
    mcc = round((vp * vn - fp * fn) / den, 4) if den else None
    return {'VP': vp, 'FN': fn, 'FP': fp, 'VN': vn, 'precision': precision, 'recall': recall,
            'especificidad': wilson(vn, vn + fp), 'tasa_fp': wilson(fp, fp + vn), 'tasa_fn': wilson(fn, fn + vp),
            'exactitud': wilson(vp + vn, vp + vn + fp + fn), 'f1': f1, 'mcc': mcc}


def leer_jsonl(ruta):
    filas = []
    if ruta and os.path.exists(ruta):
        with open(ruta, encoding='utf-8') as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    try:
                        filas.append(json.loads(linea))
                    except json.JSONDecodeError:
                        pass   # última línea cortada al matar el proceso
    return filas


def leer_manifiestos(rutas):
    corridas = []
    for ruta in rutas:
        base = os.path.dirname(os.path.abspath(ruta))
        for c in leer_jsonl(ruta):
            c['_dir_serie'] = base
            corridas.append(c)
    return corridas


def ruta_log(corrida, ruta):
    """Las rutas del manifiesto son absolutas en la máquina de la corrida; si la serie se movió,
    se busca el mismo archivo relativo a la carpeta del manifiesto."""
    if ruta and os.path.exists(ruta):
        return ruta
    if not ruta:
        return None
    partes = ruta.split(os.sep)
    candidata = os.path.join(corrida['_dir_serie'], *partes[-2:])
    return candidata if os.path.exists(candidata) else None


# ═════════════════════════════════════════════════════════════════════════════
#  Ryu: log y víctimas
# ═════════════════════════════════════════════════════════════════════════════

def metricas_ryu(ruta):
    """{ip: {'metricas': [...], 'puntaje_max': int}} desde el log de Ryu."""
    por_host = {}
    if not ruta:
        return por_host
    with open(ruta, encoding='utf-8', errors='replace') as f:
        for linea in f:
            m = RE_METRICA_RYU.search(linea)
            if not m:
                continue
            h = por_host.setdefault(m['ip'], {'metricas': [], 'puntaje_max': 0})
            if m['m'] not in h['metricas']:
                h['metricas'].append(m['m'])
            h['puntaje_max'] = max(h['puntaje_max'], int(m['p']))
    return por_host


def contencion(corrida, atacante, t_bloqueo):
    """Conexiones aceptadas por las víctimas desde el atacante, antes y después del bloqueo."""
    alcanzados, post = set(), 0
    for ruta in corrida.get('logs', {}).get('victimas', {}).values():
        for fila in leer_jsonl(ruta_log(corrida, ruta)):
            if fila.get('ip_origen') != atacante:
                continue
            ts = fecha(fila.get('ts'))
            if t_bloqueo is not None and ts is not None and ts > t_bloqueo:
                post += 1
            else:
                alcanzados.add(fila.get('ip_local'))
    return {'equipos_alcanzados_antes_del_bloqueo': len(alcanzados), 'conexiones_aceptadas_tras_bloqueo': post}


# ═════════════════════════════════════════════════════════════════════════════
#  Agente
# ═════════════════════════════════════════════════════════════════════════════

class Agente:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip('/'), token

    def _get(self, ruta):
        req = urllib.request.Request(self.url + ruta, headers={'X-Operador-Token': self.token})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode('utf-8'))

    def incidentes(self):
        todos, offset = [], 0
        while True:
            pagina = self._get(f'/api/incidentes?origen=real&limite=200&offset={offset}')
            todos += pagina
            if len(pagina) < 200:
                return todos
            offset += 200

    def detalle(self, incidente_id):
        return self._get(f'/api/incidentes/{incidente_id}')


def buscar(dic, *ruta):
    for clave in ruta:
        if not isinstance(dic, dict):
            return None
        dic = dic.get(clave)
    return dic


def emparejar(corrida, incidentes, margen_s=120):
    """Incidentes del agente cuya host_origen está bloqueada en la corrida y cuyo t_ryu cae en su ventana."""
    ips = {b['ip'] for b in corrida.get('bloqueados', [])}
    ini = fecha(corrida.get('t_inicio'))
    fin = fecha(corrida.get('t_fin'))
    if not ips or ini is None or fin is None:
        return []
    desde, hasta = ini - timedelta(seconds=5), fin + timedelta(seconds=margen_s)
    elegidos = []
    for inc in incidentes:
        t = fecha(inc.get('t_ryu')) or fecha(inc.get('t_recibido'))
        if inc.get('host_origen') in ips and t is not None and desde <= t <= hasta:
            elegidos.append(inc)
    return sorted(elegidos, key=lambda i: i['id'])


def textos_explicacion(det):
    informe = det.get('informe') or {}
    simple = informe.get('explicacion_simple') or {}
    partes = [det.get('explicacion') or '', ' '.join(det.get('evidencias') or [])]
    partes += [str(simple.get(b) or '') for b in ('que_paso', 'por_que', 'podria_equivocarnos')]
    partes += [f.get('factor', '') + ' ' + f.get('porque', '')
               for f in buscar(informe, 'razonamiento', 'factores_ponderados') or []]
    return '\n'.join(partes)


def datos_incidente(det, etiqueta):
    informe = det.get('informe') or {}
    superados = det.get('umbrales_superados') or buscar(informe, 'evidencia_objetiva', 'umbrales_superados_ryu') or []
    texto = textos_explicacion(det)
    mencionadas = [m for m in superados if re.search(PATRONES_METRICA.get(m, r'$^'), texto, re.IGNORECASE)]
    accion = buscar(informe, 'trazabilidad_y_accion', 'escalera', 'accion_recomendada')
    reglas = ACEPTABLES[etiqueta]
    fuentes_bloques = buscar(informe, 'explicacion_simple', 'fuentes') or {}
    veredicto = det.get('veredicto')
    t = {k: fecha(det.get(k)) for k in ('t_ryu', 't_recibido', 't_explicado', 't_notificado', 't_desbloqueado')}
    return {
        'incidente_id': det.get('id'), 'veredicto': veredicto, 'veredicto_llm': det.get('veredicto_llm'),
        'veredicto_correcto': veredicto == VEREDICTO_ESPERADO[etiqueta] if veredicto else None,
        'abstencion': veredicto == 'indeterminado',
        'fuente_explicacion': det.get('fuente_explicacion'), 'motivo_respaldo': det.get('motivo_respaldo'),
        'verificacion': buscar(informe, 'razonamiento', 'verificacion', 'resultado'),
        'umbrales_superados': superados, 'metricas_mencionadas': mencionadas,
        'cobertura': round(len(mencionadas) / len(superados), 4) if superados else None,
        'bloques_llm': sum(1 for v in fuentes_bloques.values() if v == 'llm'),
        'bloques_plantilla': sum(1 for v in fuentes_bloques.values() if v == 'reglas'),
        'confianza_calculada': buscar(informe, 'trazabilidad_y_accion', 'confianza_calculada', 'total'),
        'accion_recomendada': accion,
        'accion_preferida': accion in reglas['preferidas'] if accion else None,
        'accion_aceptable': accion in reglas['aceptables'] if accion else None,
        'accion_insegura': accion in reglas['inseguras'] if accion else None,
        'clasificacion_operador': det.get('clasificacion_operador'),
        't_alerta_s': segundos(t['t_ryu'], t['t_recibido']),
        't_explicacion_s': segundos(t['t_recibido'], t['t_explicado']),
        't_notificacion_s': segundos(t['t_explicado'], t['t_notificado']),
        't_desbloqueo_s': segundos(t['t_notificado'], t['t_desbloqueado']),
        '_t': t,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  Métricas por corrida y agregadas
# ═════════════════════════════════════════════════════════════════════════════

def evaluar_corrida(c, incidentes, agente):
    etiqueta = c['etiqueta']
    bloqueados = {b['ip']: b for b in c.get('bloqueados', [])}
    sospechosos = set(c.get('sospechosos') or [])
    t_inicio = fecha(c.get('t_inicio'))
    if etiqueta == 'ataque':
        detectado = bool(sospechosos & set(bloqueados))
        colaterales = sorted(set(bloqueados) - sospechosos)
    else:
        detectado = bool(bloqueados)
        colaterales = sorted(bloqueados)
    atacante = next(iter(sorted(sospechosos & set(bloqueados))), None) or next(iter(sorted(bloqueados)), None)
    t_bloqueo = fecha(bloqueados[atacante]['desde']) if atacante else None
    ryu = metricas_ryu(ruta_log(c, c.get('logs', {}).get('ryu')))
    origen = (sorted(sospechosos) or c.get('origenes') or [None])[0]
    # métricas de los hosts que originan tráfico (en un benigno pueden ser varios) y del bloqueado
    hosts = [atacante] if atacante else sorted(set(sospechosos) | set(c.get('origenes') or []))
    disparadas = sorted({m for h in hosts for m in ryu.get(h, {}).get('metricas', [])})
    puntaje_max = max([ryu.get(h, {}).get('puntaje_max', 0) for h in hosts] or [0])
    fila = {
        'corrida_id': c.get('corrida_id'), 'bloque': c.get('bloque'), 'escenario': c['escenario'],
        'repeticion': c.get('repeticion'), 'etiqueta': etiqueta, 'dificil': c.get('dificil', False),
        'error': c.get('error'), 'detectado': detectado, 'host_bloqueado': atacante,
        'bloqueos_colaterales': colaterales,
        'drop_en_3_switches': (len(c.get('drop_en_switches', {}).get(atacante, [])) == 3) if atacante else None,
        'metricas_ryu': disparadas,
        'puntaje_max_ryu': puntaje_max,
        'metricas_previstas': c.get('metricas_previstas', []),
        't_deteccion_s': segundos(t_inicio, t_bloqueo),
        **({} if etiqueta != 'ataque' else contencion(c, origen, t_bloqueo)),
    }
    fila['metricas_coinciden_con_previstas'] = sorted(fila['metricas_ryu']) == sorted(fila['metricas_previstas'])
    if agente is not None and detectado:
        emparejados = emparejar(c, incidentes)
        fila['incidentes'] = [i['id'] for i in emparejados]
        if emparejados:
            datos = datos_incidente(agente.detalle(emparejados[0]['id']), etiqueta)
            t = datos.pop('_t')
            datos['t_total_hasta_operador_s'] = segundos(t_inicio, t['t_notificado'])
            fila.update(datos)
    return fila


def proporcion(filas, campo):
    validas = [f[campo] for f in filas if f.get(campo) is not None]
    return wilson(sum(1 for v in validas if v), len(validas))


def resumen_explicaciones(filas):
    con = [f for f in filas if f.get('incidente_id')]
    decididas = [f for f in con if f.get('veredicto') and not f['abstencion']]
    return {
        'incidentes': len(con),
        'fuente': dict(Counter(f.get('fuente_explicacion') for f in con)),
        'motivos_respaldo': dict(Counter(f['motivo_respaldo'] for f in con if f.get('motivo_respaldo'))),
        'concordancia_veredicto_etiqueta': wilson(sum(1 for f in decididas if f['veredicto_correcto']), len(decididas)),
        'concordancia_incluyendo_abstenciones': proporcion(con, 'veredicto_correcto'),
        'tasa_abstencion': proporcion(con, 'abstencion'),
        'verificadas_sin_alucinacion': wilson(sum(1 for f in con if f.get('verificacion') == 'verificado'),
                                              sum(1 for f in con if f.get('verificacion'))),
        'cobertura_metricas': describir([f.get('cobertura') for f in con]),
        'bloques_reemplazados_por_plantilla': describir([f.get('bloques_plantilla') for f in con]),
        'veredictos': dict(Counter(f.get('veredicto') for f in con)),
    }


def resumen(filas):
    validas = [f for f in filas if not f.get('error')]
    detectadas = [f for f in validas if f['detectado']]
    ataques_det = [f for f in detectadas if f['etiqueta'] == 'ataque']
    con_inc = [f for f in validas if f.get('incidente_id')]
    out = {
        'corridas': {'total': len(filas), 'validas': len(validas), 'con_error': len(filas) - len(validas),
                     'por_escenario': dict(Counter(f['escenario'] for f in validas))},
        'deteccion': {
            'global': confusion(validas),
            'sin_casos_dificiles': confusion([f for f in validas if not f['dificil']]),
            'por_escenario': {
                e: {'etiqueta': grupo[0]['etiqueta'], 'dificil': grupo[0]['dificil'],
                    'tasa_bloqueo': wilson(sum(1 for f in grupo if f['detectado']), len(grupo)),
                    'metricas_ryu': dict(Counter(m for f in grupo for m in f['metricas_ryu'])),
                    'combinaciones': dict(Counter('+'.join(sorted(f['metricas_ryu'])) or 'ninguna' for f in grupo)),
                    'metricas_previstas': grupo[0]['metricas_previstas'],
                    'coinciden_con_previstas': wilson(sum(1 for f in grupo if f['metricas_coinciden_con_previstas']),
                                                      len(grupo)),
                    'puntaje_max_ryu': describir([f['puntaje_max_ryu'] for f in grupo]),
                    't_deteccion_s': describir([f['t_deteccion_s'] for f in grupo])}
                for e, grupo in sorted(_agrupar(validas, 'escenario').items())},
            'bloqueos_colaterales': sum(len(f['bloqueos_colaterales']) for f in validas if f['etiqueta'] == 'ataque'),
            'metricas_m1_m5': {m: {'corridas': sum(1 for f in validas if m in f['metricas_ryu']),
                                   'escenarios': sorted({f['escenario'] for f in validas if m in f['metricas_ryu']})}
                               for m in METRICAS},
        },
        'contencion': {
            'drop_en_3_switches': proporcion(detectadas, 'drop_en_3_switches'),
            # el orquestador nunca desbloquea: cualquier t_desbloqueado sería una liberación sin operador
            'desbloqueos_sin_operador': sum(1 for f in con_inc if f.get('t_desbloqueo_s') is not None),
            'conexiones_aceptadas_tras_bloqueo': describir([f.get('conexiones_aceptadas_tras_bloqueo')
                                                            for f in ataques_det]),
            'equipos_alcanzados_antes_del_bloqueo': describir([f.get('equipos_alcanzados_antes_del_bloqueo')
                                                               for f in ataques_det]),
        },
        'tiempos_s': {
            'deteccion_y_bloqueo': describir([f['t_deteccion_s'] for f in ataques_det]),
            'entrega_alerta': describir([f.get('t_alerta_s') for f in con_inc]),
            'explicacion': describir([f.get('t_explicacion_s') for f in con_inc]),
            'explicacion_llm': describir([f.get('t_explicacion_s') for f in con_inc
                                          if f.get('fuente_explicacion') == 'llm']),
            'explicacion_reglas': describir([f.get('t_explicacion_s') for f in con_inc
                                             if f.get('fuente_explicacion') == 'reglas']),
            'notificacion': describir([f.get('t_notificacion_s') for f in con_inc]),
            'total_hasta_operador': describir([f.get('t_total_hasta_operador_s') for f in con_inc]),
            'decision_operador_desbloqueo': describir([f.get('t_desbloqueo_s') for f in con_inc]),
        },
        'explicacion': {
            'global': resumen_explicaciones(validas),
            'por_fuente': {fuente: resumen_explicaciones([f for f in con_inc if f.get('fuente_explicacion') == fuente])
                           for fuente in sorted({f.get('fuente_explicacion') for f in con_inc} - {None})},
            'por_bloque': {b: resumen_explicaciones(g) for b, g in sorted(_agrupar(validas, 'bloque').items())},
        },
        'recomendacion': {
            'acciones': {e: dict(Counter(f.get('accion_recomendada') for f in g if f.get('incidente_id')))
                         for e, g in sorted(_agrupar(validas, 'escenario').items())},
            'pertinente_preferida': proporcion(con_inc, 'accion_preferida'),
            'aceptable': proporcion(con_inc, 'accion_aceptable'),
            'insegura': proporcion(con_inc, 'accion_insegura'),
        },
        'llm_frente_a_reglas': comparar_bloques(validas),
    }
    return out


def _agrupar(filas, campo):
    grupos = defaultdict(list)
    for f in filas:
        grupos[f.get(campo)].append(f)
    return grupos


# ═════════════════════════════════════════════════════════════════════════════
#  Salidas
# ═════════════════════════════════════════════════════════════════════════════

COLUMNAS_CSV = [
    'corrida_id', 'bloque', 'escenario', 'repeticion', 'etiqueta', 'dificil', 'error', 'detectado', 'host_bloqueado',
    'bloqueos_colaterales', 'drop_en_3_switches', 'metricas_ryu', 'metricas_previstas', 'puntaje_max_ryu',
    't_deteccion_s', 'equipos_alcanzados_antes_del_bloqueo', 'conexiones_aceptadas_tras_bloqueo', 'incidente_id',
    'veredicto', 'veredicto_llm', 'veredicto_correcto', 'fuente_explicacion', 'motivo_respaldo', 'verificacion',
    'cobertura', 'bloques_plantilla', 'confianza_calculada', 'accion_recomendada', 'accion_aceptable',
    'accion_insegura', 't_alerta_s', 't_explicacion_s', 't_notificacion_s', 't_total_hasta_operador_s',
    't_desbloqueo_s',
]


def _celda(v):
    if isinstance(v, (list, tuple)):
        return '|'.join(map(str, v))
    return '' if v is None else v


def escribir_csv(ruta, filas, columnas):
    with open(ruta, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=columnas, extrasaction='ignore')
        w.writeheader()
        for fila in filas:
            w.writerow({c: _celda(fila.get(c)) for c in columnas})


def _pct(p):
    if not p or p.get('valor') is None:
        return 'n/d'
    return f"{100 * p['valor']:.1f} % [{100 * p['ic95'][0]:.1f}–{100 * p['ic95'][1]:.1f}] ({p['k']}/{p['n']})"


def _t(d):
    if not d or not d.get('n'):
        return 'n/d'
    return f"mediana {d['mediana']} s · p95 {d['p95']} s · media {d['media']} s (n={d['n']})"


def markdown(res):
    d = res['deteccion']['global']
    t0, x0, r0, c0 = res['tiempos_s'], res['explicacion']['global'], res['recomendacion'], res['contencion']
    lineas = [
        '# Resultados de la evaluación R4 (objetivo 3)', '',
        f"Corridas válidas: {res['corridas']['validas']} de {res['corridas']['total']}.", '',
        '## Cumplimiento del objetivo 3', '',
        'Objetivo: evaluar el desempeño del prototipo mediante métricas de precisión, tasa de falsos '
        'positivos/negativos, calidad de las recomendaciones y tiempos de respuesta.', '',
        '| Indicador del objetivo | Resultado | Componente |', '|---|---|---|',
        f"| Precisión de la detección | {_pct(d['precision'])} | Ryu |",
        f"| Exhaustividad (ataques detectados) | {_pct(d['recall'])} | Ryu |",
        f"| Tasa de falsos positivos | {_pct(d['tasa_fp'])} | Ryu |",
        f"| Tasa de falsos negativos | {_pct(d['tasa_fn'])} | Ryu |",
        f"| F1 · MCC | {d['f1']} · {d['mcc']} | Ryu |",
        f"| Contención en los 3 switches | {_pct(c0['drop_en_3_switches'])} | Ryu |",
        f"| Tiempo de detección y bloqueo | {_t(t0['deteccion_y_bloqueo'])} | Ryu |",
        f"| Concordancia del veredicto con la etiqueta | {_pct(x0['concordancia_veredicto_etiqueta'])} | Agente |",
        f"| Explicaciones sin cifras inventadas | {_pct(x0['verificadas_sin_alucinacion'])} | Agente |",
        f"| Recomendación pertinente (preferida) | {_pct(r0['pertinente_preferida'])} | Agente |",
        f"| Recomendación insegura (relaja un ataque) | {_pct(r0['insegura'])} | Agente |",
        f"| Tiempo hasta el operador (inicio → correo) | {_t(t0['total_hasta_operador'])} | Ryu + agente |",
        f"| Desbloqueos sin operador | {res['contencion'].get('desbloqueos_sin_operador', 'n/d')} (debe ser 0) | Ryu + agente |",
        '',
        '## Detección (Ryu, por corrida; IC de Wilson al 95 %)', '',
        f"| VP | FN | FP | VN |\n|---|---|---|---|\n| {d['VP']} | {d['FN']} | {d['FP']} | {d['VN']} |", '',
        f"- Precisión: {_pct(d['precision'])}", f"- Exhaustividad (recall): {_pct(d['recall'])}",
        f"- Tasa de falsos positivos: {_pct(d['tasa_fp'])}", f"- Tasa de falsos negativos: {_pct(d['tasa_fn'])}",
        f"- F1: {d['f1']} · MCC: {d['mcc']} · Exactitud: {_pct(d['exactitud'])}",
        f"- Sin casos difíciles: F1 {res['deteccion']['sin_casos_dificiles']['f1']}, "
        f"tasa FP {_pct(res['deteccion']['sin_casos_dificiles']['tasa_fp'])}", '',
        '| Escenario | Etiqueta | Bloqueo | Métricas observadas (corridas) | Previstas | Puntaje (mediana) | Detección |',
        '|---|---|---|---|---|---|---|',
    ]
    for e, r in res['deteccion']['por_escenario'].items():
        lineas.append(f"| {e}{' *' if r['dificil'] else ''} | {r['etiqueta']} | {_pct(r['tasa_bloqueo'])} | "
                      f"{', '.join(f'{k}: {v}' for k, v in r['combinaciones'].items())} | "
                      f"{'+'.join(r['metricas_previstas']) or 'ninguna'} | {r['puntaje_max_ryu'].get('mediana')} | "
                      f"{_t(r['t_deteccion_s'])} |")
    lineas += ['', '\\* caso difícil por diseño.', '', '## Métricas M1 a M5', '',
               '| Métrica | Corridas en que se disparó | Escenarios |', '|---|---|---|']
    for m, r in res['deteccion']['metricas_m1_m5'].items():
        lineas.append(f"| {m} | {r['corridas']} | {', '.join(r['escenarios']) or 'ninguno'} |")
    c, t, x, rec = res['contencion'], res['tiempos_s'], res['explicacion']['global'], res['recomendacion']
    lineas += [
        '', '## Contención', '',
        f"- DROP en los 3 switches: {_pct(c['drop_en_3_switches'])}",
        f"- Conexiones del atacante aceptadas tras el bloqueo: {c['conexiones_aceptadas_tras_bloqueo']}",
        f"- Equipos alcanzados antes del bloqueo: {c['equipos_alcanzados_antes_del_bloqueo']}", '',
        '## Tiempos', '',
        f"- Detección y bloqueo (inicio → DROP): {_t(t['deteccion_y_bloqueo'])}",
    ]
    if not x['incidentes']:
        lineas += ['', 'Sin incidentes del agente: el informe cubre solo la detección y la contención de Ryu.']
        return '\n'.join(lineas) + '\n'
    lineas += [
        f"- Entrega de la alerta (t_ryu → t_recibido): {_t(t['entrega_alerta'])}",
        f"- Explicación: {_t(t['explicacion'])} (LLM: {_t(t['explicacion_llm'])}; reglas: {_t(t['explicacion_reglas'])})",
        f"- Notificación: {_t(t['notificacion'])}",
        f"- Total hasta el operador (inicio → correo): {_t(t['total_hasta_operador'])}",
        f"- Decisión del operador (correo → desbloqueo): {_t(t['decision_operador_desbloqueo'])}", '',
        '## Explicación y recomendación', '',
        f"- Incidentes emparejados: {x['incidentes']} · fuente: {x['fuente']}",
        f"- Concordancia del veredicto con la etiqueta (sin abstenciones): {_pct(x['concordancia_veredicto_etiqueta'])}",
        f"- Abstención (indeterminado): {_pct(x['tasa_abstencion'])}",
        f"- Explicaciones verificadas sin cifras inventadas: {_pct(x['verificadas_sin_alucinacion'])}",
        f"- Cobertura de las métricas disparadas: {x['cobertura_metricas']}",
        f"- Recomendación preferida: {_pct(rec['pertinente_preferida'])} · aceptable: {_pct(rec['aceptable'])} · "
        f"insegura: {_pct(rec['insegura'])}",
    ]
    comp = res.get('llm_frente_a_reglas')
    if comp:
        lineas += ['', '## LLM frente a reglas', '',
                   'Misma serie de escenarios con el LLM activo y con el LLM apagado (respaldo por reglas). '
                   'Proporciones: prueba exacta de Fisher; tiempos: U de Mann-Whitney con delta de Cliff.', '',
                   '| Indicador | LLM | Reglas | p |', '|---|---|---|---|']
        for clave, nombre in (('concordancia_veredicto', 'Concordancia del veredicto'), ('abstencion', 'Abstención'),
                              ('accion_preferida', 'Recomendación preferida'), ('accion_insegura', 'Recomendación insegura')):
            fila = comp[clave]
            lineas.append(f"| {nombre} | {_pct(fila['llm'])} | {_pct(fila['reglas'])} | {fila['p_fisher']} |")
        for clave, nombre in (('t_explicacion_s', 'Tiempo de explicación'), ('t_total_hasta_operador_s', 'Tiempo hasta el operador')):
            mw = comp[clave]
            lineas.append(f"| {nombre} | n={mw['n1']} | n={mw['n2']} | {mw['p']} (delta de Cliff {mw['delta_cliff']}) |")
    return '\n'.join(lineas) + '\n'


# ═════════════════════════════════════════════════════════════════════════════
#  Calificación humana a ciegas
# ═════════════════════════════════════════════════════════════════════════════

CRITERIOS = ('comprensible', 'fiel_a_los_datos', 'completa', 'accionable')


def plantilla(corridas, agente, salida, semilla):
    incidentes = agente.incidentes()
    filas, clave = [], []
    for c in corridas:
        for inc in emparejar(c, incidentes)[:1]:
            det = agente.detalle(inc['id'])
            simple = buscar(det, 'informe', 'explicacion_simple') or {}
            filas.append({'que_paso': simple.get('que_paso') or det.get('explicacion') or '',
                          'por_que': simple.get('por_que') or '',
                          'podria_equivocarnos': simple.get('podria_equivocarnos') or '',
                          'que_recomendamos': str(simple.get('que_recomendamos') or det.get('recomendacion_operador') or ''),
                          '_id': det['id'], '_fuente': det.get('fuente_explicacion'),
                          '_escenario': c['escenario'], '_etiqueta': c['etiqueta']})
    rng = random.Random(semilla)
    rng.shuffle(filas)
    for i, f in enumerate(filas, 1):
        f['codigo'] = f'E{i:03d}'
        clave.append({'codigo': f['codigo'], 'incidente_id': f['_id'], 'fuente': f['_fuente'],
                      'escenario': f['_escenario'], 'etiqueta': f['_etiqueta']})
    os.makedirs(salida, exist_ok=True)
    columnas = ['codigo', 'que_paso', 'por_que', 'podria_equivocarnos', 'que_recomendamos', *CRITERIOS, 'comentario']
    escribir_csv(os.path.join(salida, 'plantilla_calificacion.csv'), filas, columnas)
    escribir_csv(os.path.join(salida, 'clave_calificacion.csv'), clave,
                 ['codigo', 'incidente_id', 'fuente', 'escenario', 'etiqueta'])
    return len(filas)


def alfa_krippendorff_ordinal(unidades):
    """Alfa de Krippendorff con métrica ordinal (Hayes y Krippendorff, 2007).
    unidades: lista de listas con los valores (enteros) que dieron los evaluadores a cada unidad."""
    pares = [[v for v in u if v is not None] for u in unidades]
    pares = [u for u in pares if len(u) >= 2]
    valores = sorted({v for u in pares for v in u})
    if len(valores) < 2:
        return 1.0 if pares else None
    idx = {v: i for i, v in enumerate(valores)}
    k = len(valores)
    o = [[0.0] * k for _ in range(k)]
    for u in pares:
        m = len(u)
        for i, a in enumerate(u):
            for j, b in enumerate(u):
                if i != j:
                    o[idx[a]][idx[b]] += 1 / (m - 1)
    n_c = [sum(fila) for fila in o]
    n = sum(n_c)

    def delta2(c, d):
        c, d = min(c, d), max(c, d)
        return (sum(n_c[c:d + 1]) - (n_c[c] + n_c[d]) / 2) ** 2

    do = sum(o[c][d] * delta2(c, d) for c in range(k) for d in range(k))
    de = sum(n_c[c] * n_c[d] * delta2(c, d) for c in range(k) for d in range(k))
    if de == 0:
        return 1.0
    return round(1 - (n - 1) * do / de, 4)


def calificaciones(ruta_clave, rutas_eval):
    with open(ruta_clave, encoding='utf-8') as f:
        clave = {r['codigo']: r for r in csv.DictReader(f)}
    notas = defaultdict(dict)   # (codigo, criterio) → {evaluador: valor}
    for n_eval, ruta in enumerate(rutas_eval):
        with open(ruta, encoding='utf-8') as f:
            for r in csv.DictReader(f):
                for crit in CRITERIOS:
                    v = (r.get(crit) or '').strip()
                    if v.isdigit() and 1 <= int(v) <= 5:
                        notas[(r['codigo'], crit)][n_eval] = int(v)
    out = {'evaluadores': len(rutas_eval), 'unidades': len(clave), 'criterios': {}}
    for crit in CRITERIOS:
        por_fuente = defaultdict(list)
        unidades = []
        for codigo, info in clave.items():
            vals = notas.get((codigo, crit), {})
            if vals:
                por_fuente[info['fuente']].append(statistics.mean(vals.values()))
                unidades.append(list(vals.values()))
        out['criterios'][crit] = {
            'alfa_krippendorff_ordinal': alfa_krippendorff_ordinal(unidades),
            'por_fuente': {fte: describir(v) for fte, v in sorted(por_fuente.items())},
            'global': describir([x for v in por_fuente.values() for x in v]),
        }
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

def _agente(args):
    token = os.environ.get('OPERADOR_TOKEN', '')
    if not token:
        raise SystemExit('Falta OPERADOR_TOKEN (la del .env del agente), o usa --sin-agente')
    return Agente(os.environ.get('AGENTE_URL', 'http://127.0.0.1:8081'), token)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='modo', required=True)
    m = sub.add_parser('metricas')
    m.add_argument('manifiestos', nargs='+')
    m.add_argument('--salida')
    m.add_argument('--sin-agente', action='store_true', help='solo métricas de Ryu (sin explicación ni tiempos del agente)')
    p = sub.add_parser('plantilla')
    p.add_argument('manifiestos', nargs='+')
    p.add_argument('--salida', required=True)
    p.add_argument('--semilla', type=int, default=7)
    k = sub.add_parser('calificaciones')
    k.add_argument('--clave', required=True)
    k.add_argument('evaluaciones', nargs='+')
    k.add_argument('--salida')
    args = parser.parse_args(argv)

    if args.modo == 'calificaciones':
        out = calificaciones(args.clave, args.evaluaciones)
        texto = json.dumps(out, indent=2, ensure_ascii=False)
        if args.salida:
            with open(args.salida, 'w', encoding='utf-8') as f:
                f.write(texto)
        print(texto)
        return 0

    corridas = leer_manifiestos(args.manifiestos)
    if args.modo == 'plantilla':
        n = plantilla(corridas, _agente(args), args.salida, args.semilla)
        print(f'{n} explicaciones en {args.salida}/plantilla_calificacion.csv (la clave va aparte; no se la des a los evaluadores)')
        return 0

    agente = None if args.sin_agente else _agente(args)
    incidentes = agente.incidentes() if agente else []
    filas = [evaluar_corrida(c, incidentes, agente) for c in corridas]
    res = resumen(filas)
    salida = args.salida or os.path.dirname(os.path.abspath(args.manifiestos[0]))
    os.makedirs(salida, exist_ok=True)
    with open(os.path.join(salida, 'evaluacion.json'), 'w', encoding='utf-8') as f:
        json.dump({'resumen': res, 'corridas': filas}, f, indent=2, ensure_ascii=False, default=str)
    escribir_csv(os.path.join(salida, 'corridas.csv'), filas, COLUMNAS_CSV)
    with open(os.path.join(salida, 'resumen.md'), 'w', encoding='utf-8') as f:
        f.write(markdown(res))
    print(markdown(res))
    print(f'Archivos: {salida}/evaluacion.json, corridas.csv, resumen.md')
    return 0


if __name__ == '__main__':
    sys.exit(main())
