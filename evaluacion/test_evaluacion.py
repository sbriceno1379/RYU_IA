#!/usr/bin/env python3
"""Pruebas sin sudo ni Mininet de los scripts de evaluación (solo librería estándar).

    python3 -m unittest evaluacion/test_evaluacion.py -v
"""

import json
import os
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from contextlib import redirect_stdout

DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, DIR)

import correr_evaluacion  # noqa: E402
import evaluar      # noqa: E402
import orquestador  # noqa: E402
import trafico      # noqa: E402


def puerto_libre():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class TestTrafico(unittest.TestCase):
    def test_expandir(self):
        self.assertEqual(trafico.expandir_destinos('10.0.10.2-4,10.0.20.1'),
                         ['10.0.10.2', '10.0.10.3', '10.0.10.4', '10.0.20.1'])
        self.assertEqual(trafico.expandir_puertos('445,135'), [445, 135])

    def test_victima_y_conexiones_en_localhost(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1, p2 = puerto_libre(), puerto_libre()
            log_v, log_a = os.path.join(tmp, 'v.jsonl'), os.path.join(tmp, 'a.jsonl')
            victima = subprocess.Popen([sys.executable, os.path.join(DIR, 'trafico.py'), 'victima',
                                        '--ip', '127.0.0.1', '--puertos', f'{p1},{p2}', '--log', log_v],
                                       stdout=subprocess.PIPE)
            try:
                victima.stdout.readline()   # "[victima] escuchando ..."
                trafico.main(['conexiones', '--destinos', '127.0.0.1', '--puertos', f'{p1},{p2},1',
                              '--bytes', '100000', '--intervalo', '0', '--ciclos', '2', '--log', log_a])
                limite = time.time() + 5   # la víctima escribe al cerrar cada conexión
                while len(evaluar.leer_jsonl(log_v)) < 4 and time.time() < limite:
                    time.sleep(0.1)
            finally:
                victima.terminate()
                victima.wait(5)
            intentos = evaluar.leer_jsonl(log_a)
            self.assertEqual(len(intentos), 6)
            self.assertEqual(sum(1 for i in intentos if i['ok']), 4)         # el puerto 1 está cerrado
            recibidas = evaluar.leer_jsonl(log_v)
            self.assertEqual(len(recibidas), 4)
            self.assertTrue(all(r['bytes'] == 100000 and r['ip_origen'] == '127.0.0.1' for r in recibidas))


class TestOrquestador(unittest.TestCase):
    def setUp(self):
        self.escenarios = orquestador.cargar_escenarios(os.path.join(DIR, 'escenarios_r4.json'))

    def test_escenarios_bien_formados(self):
        ids = [e['id'] for e in self.escenarios]
        self.assertEqual(len(ids), len(set(ids)))
        for e in self.escenarios:
            self.assertIn(e['etiqueta'], ('ataque', 'benigno'))
            if e['etiqueta'] == 'ataque':
                self.assertTrue(e['sospechosos'])
                self.assertEqual(e['sospechosos'], [orquestador.ip_de_host(e['procesos'][0]['host'])])
            for p in e['procesos']:
                partes = shlex.split(orquestador.comando(p['cmd'], '/tmp/x.jsonl', 1))
                if partes[1].endswith('trafico.py'):   # los argumentos deben ser válidos para trafico.py
                    parser_ok = subprocess.run([sys.executable, partes[1], *partes[2:], '--help'],
                                               capture_output=True)
                    self.assertEqual(parser_ok.returncode, 0, p['cmd'])

    def test_al_menos_un_escenario_de_dos_metricas(self):
        # PLAN del agente, Fase 6.7: al menos un escenario real que dispare solo 2 métricas
        self.assertTrue(any(len(e['metricas_previstas']) == 2 for e in self.escenarios if e['etiqueta'] == 'ataque'))

    def test_plan_aleatorio_y_reproducible(self):
        a = orquestador.armar_plan(self.escenarios, 3, 42)
        b = orquestador.armar_plan(self.escenarios, 3, 42)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 3 * len(self.escenarios))
        self.assertNotEqual([c['escenario'] for c in a], sorted(c['escenario'] for c in a))
        self.assertEqual([c['orden'] for c in a], list(range(1, len(a) + 1)))

    def test_ip_de_host(self):
        self.assertEqual(orquestador.ip_de_host('h1'), '10.0.10.1')
        self.assertEqual(orquestador.ip_de_host('h11'), '10.0.20.1')
        self.assertEqual(orquestador.ip_de_host('h20'), '10.0.20.10')

    def test_dry_run(self):
        with redirect_stdout(StringIO()) as out:
            orquestador.main(['--dry-run', '--solo', 'A2,B3', '--repeticiones', '2'])
        self.assertIn('Plan (4 corridas', out.getvalue())


class TestEstadistica(unittest.TestCase):
    def test_wilson(self):
        self.assertEqual(evaluar.wilson(5, 10)['ic95'], [0.2366, 0.7634])
        self.assertEqual(evaluar.wilson(0, 10)['ic95'], [0.0, 0.2775])
        self.assertIsNone(evaluar.wilson(0, 0)['valor'])

    def test_confusion(self):
        filas = ([{'etiqueta': 'ataque', 'detectado': True}] * 8 + [{'etiqueta': 'ataque', 'detectado': False}] * 2
                 + [{'etiqueta': 'benigno', 'detectado': True}] * 1 + [{'etiqueta': 'benigno', 'detectado': False}] * 9)
        c = evaluar.confusion(filas)
        self.assertEqual((c['VP'], c['FN'], c['FP'], c['VN']), (8, 2, 1, 9))
        self.assertEqual(c['precision']['valor'], 0.8889)
        self.assertEqual(c['recall']['valor'], 0.8)
        self.assertEqual(c['tasa_fp']['valor'], 0.1)
        self.assertEqual(c['f1'], 0.8421)
        self.assertEqual(c['mcc'], 0.7035)

    def test_alfa_krippendorff_ejemplo_canonico(self):
        # Krippendorff (2011), "Computing Krippendorff's alpha-reliability": 4 evaluadores, 12 unidades,
        # con datos faltantes. Alfa ordinal publicado: 0.815.
        n = None
        a = [1, 2, 3, 3, 2, 1, 4, 1, 2, n, n, n]
        b = [1, 2, 3, 3, 2, 2, 4, 1, 2, 5, n, 3]
        c = [n, 3, 3, 3, 2, 3, 4, 2, 2, 5, 1, n]
        d = [1, 2, 3, 3, 2, 4, 4, 1, 2, 5, 1, n]
        unidades = [list(u) for u in zip(a, b, c, d)]
        self.assertAlmostEqual(evaluar.alfa_krippendorff_ordinal(unidades), 0.815, places=3)
        self.assertEqual(evaluar.alfa_krippendorff_ordinal([[3, 3], [4, 4], [2, 2]]), 1.0)

    def test_describir(self):
        d = evaluar.describir([1, 2, 3, 4, None])
        self.assertEqual((d['n'], d['mediana'], d['p95']), (4, 2.5, 3.85))


# ─── Extremo a extremo con un agente falso ───────────────────────────────────

INCIDENTE = {
    'id': 7, 'host_origen': '10.0.10.1', 'veredicto': 'confirmado', 'veredicto_llm': 'confirmado',
    'fuente_explicacion': 'llm', 'motivo_respaldo': None, 'explicacion': 'Muchos flujos nuevos (M1) y conexiones east-west (M5).',
    'evidencias': [], 'umbrales_superados': ['M1', 'M2', 'M5'],
    't_ryu': '2026-10-28T03:00:12.500000Z', 't_recibido': '2026-10-28T03:00:12.600000Z',
    't_explicado': '2026-10-28T03:00:16.600000Z', 't_notificado': '2026-10-28T03:00:17.100000Z', 't_desbloqueado': None,
    'informe': {'razonamiento': {'verificacion': {'resultado': 'verificado'}, 'factores_ponderados': []},
                'trazabilidad_y_accion': {'escalera': {'accion_recomendada': 'cuarentena_puertos'},
                                          'confianza_calculada': {'total': 0.81}},
                'explicacion_simple': {'que_paso': 'Se aisló 10.0.10.1.', 'por_que': 'Contactó 9 destinos distintos.',
                                       'podria_equivocarnos': 'x', 'que_recomendamos': 'Cuarentena de puertos',
                                       'fuentes': {'que_paso': 'llm', 'por_que': 'llm', 'podria_equivocarnos': 'reglas'}}},
}


class AgenteFalso(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('X-Operador-Token') != 'op':
            self.send_response(401)
            self.end_headers()
            return
        cuerpo = [{k: v for k, v in INCIDENTE.items() if k != 'informe'}] if self.path.startswith('/api/incidentes?') \
            else INCIDENTE
        datos = json.dumps(cuerpo).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(datos)

    def log_message(self, *a):
        pass


class TestExtremoAExtremo(unittest.TestCase):
    def test_metricas_con_agente_falso(self):
        srv = HTTPServer(('127.0.0.1', 0), AgenteFalso)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory() as tmp:
            d1 = os.path.join(tmp, '001_A1_r01')
            os.makedirs(d1)
            with open(os.path.join(d1, 'ryu.log'), 'w') as f:
                f.write("2026-10-28T03:00:05 [WARNING] RyuSDN — [M5] 10.0.10.1 — M5: 5 flujos W2W | peso=40 | puntaje=40 | metricas=['M5']\n"
                        "2026-10-28T03:00:10 [WARNING] RyuSDN — [M1] 10.0.10.1 — M1: 21 flujos | peso=25 | puntaje=65 | metricas=['M1', 'M5']\n"
                        "2026-10-28T03:00:12 [WARNING] RyuSDN — [M2] 10.0.10.1 — M2: 9 destinos | peso=20 | puntaje=85 | metricas=['M1', 'M2', 'M5']\n")
            with open(os.path.join(d1, 'victima_h2.jsonl'), 'w') as f:
                f.write('{"ts": "2026-10-28T03:00:03Z", "ip_origen": "10.0.10.1", "ip_local": "10.0.10.2"}\n'
                        '{"ts": "2026-10-28T03:00:04Z", "ip_origen": "10.0.10.1", "ip_local": "10.0.10.3"}\n'
                        '{"ts": "2026-10-28T03:00:20Z", "ip_origen": "10.0.10.1", "ip_local": "10.0.10.2"}\n')
            corridas = [
                {'corrida_id': '001_A1_r01', 'bloque': 'llm', 'escenario': 'A1', 'repeticion': 1, 'etiqueta': 'ataque',
                 'dificil': False, 'sospechosos': ['10.0.10.1'], 'metricas_previstas': ['M1', 'M2', 'M5'],
                 't_inicio': '2026-10-28T03:00:00Z', 't_fin': '2026-10-28T03:00:35Z',
                 'bloqueados': [{'ip': '10.0.10.1', 'desde': '2026-10-28T03:00:12.400000Z', 'modo': 'drop_total'}],
                 'drop_en_switches': {'10.0.10.1': ['s1', 's2', 's3']}, 'error': None,
                 'logs': {'ryu': '/otra/maquina/001_A1_r01/ryu.log',
                          'victimas': {'h2': '/otra/maquina/001_A1_r01/victima_h2.jsonl'}}},
                {'corrida_id': '002_B1_r01', 'bloque': 'llm', 'escenario': 'B1', 'repeticion': 1, 'etiqueta': 'benigno',
                 'dificil': False, 'sospechosos': [], 'metricas_previstas': [], 't_inicio': '2026-10-28T03:05:00Z',
                 't_fin': '2026-10-28T03:07:00Z', 'bloqueados': [], 'drop_en_switches': {}, 'error': None, 'logs': {}},
            ]
            manifiesto = os.path.join(tmp, 'manifiesto.jsonl')
            with open(manifiesto, 'w') as f:
                f.writelines(json.dumps(c) + '\n' for c in corridas)
            os.environ.update(OPERADOR_TOKEN='op', AGENTE_URL=f'http://127.0.0.1:{srv.server_port}')
            try:
                with redirect_stdout(StringIO()):
                    evaluar.main(['metricas', manifiesto])
                    evaluar.main(['plantilla', manifiesto, '--salida', os.path.join(tmp, 'cal')])
            finally:
                srv.shutdown()
            with open(os.path.join(tmp, 'evaluacion.json')) as f:
                datos = json.load(f)
            self.assertEqual(datos['resumen']['deteccion']['metricas_m1_m5']['M3']['corridas'], 0)
            res, a1 = datos['resumen'], datos['corridas'][0]
            self.assertEqual((res['deteccion']['global']['VP'], res['deteccion']['global']['VN']), (1, 1))
            self.assertEqual(a1['t_deteccion_s'], 12.4)
            self.assertEqual(a1['metricas_ryu'], ['M1', 'M2', 'M5'])
            self.assertTrue(a1['metricas_coinciden_con_previstas'])
            self.assertEqual(a1['puntaje_max_ryu'], 85)
            self.assertEqual((a1['equipos_alcanzados_antes_del_bloqueo'], a1['conexiones_aceptadas_tras_bloqueo']), (2, 1))
            self.assertTrue(a1['drop_en_3_switches'])
            self.assertEqual(a1['incidente_id'], 7)
            self.assertTrue(a1['veredicto_correcto'])
            self.assertEqual(a1['metricas_mencionadas'], ['M1', 'M2', 'M5'])
            self.assertEqual(a1['t_explicacion_s'], 4.0)
            self.assertEqual(a1['t_total_hasta_operador_s'], 17.1)
            self.assertTrue(a1['accion_preferida'])
            self.assertFalse(a1['accion_insegura'])
            self.assertEqual(a1['bloques_plantilla'], 1)
            self.assertTrue(os.path.exists(os.path.join(tmp, 'corridas.csv')))
            self.assertTrue(os.path.exists(os.path.join(tmp, 'resumen.md')))
            # plantilla a ciegas: sin la fuente ni el id del incidente
            with open(os.path.join(tmp, 'cal', 'plantilla_calificacion.csv')) as f:
                cabecera = f.readline()
            self.assertNotIn('fuente', cabecera)
            self.assertNotIn('incidente', cabecera)


    def test_solo_ryu_sin_agente(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifiesto = os.path.join(tmp, 'manifiesto.jsonl')
            with open(manifiesto, 'w') as f:
                f.write(json.dumps({'corrida_id': 'x', 'escenario': 'B3', 'repeticion': 1, 'etiqueta': 'benigno',
                                    'dificil': True, 'sospechosos': [], 'origenes': ['10.0.20.1'],
                                    'metricas_previstas': ['M1', 'M4', 'M5'], 't_inicio': '2026-10-28T03:00:00Z',
                                    't_fin': '2026-10-28T03:01:00Z', 'error': None, 'logs': {},
                                    'bloqueados': [{'ip': '10.0.20.1', 'desde': '2026-10-28T03:00:09Z'}],
                                    'drop_en_switches': {'10.0.20.1': ['s1', 's2', 's3']}}) + '\n')
            with redirect_stdout(StringIO()):
                evaluar.main(['metricas', manifiesto, '--sin-agente'])
            with open(os.path.join(tmp, 'resumen.md')) as f:
                md = f.read()
            self.assertIn('## Métricas M1 a M5', md)
            self.assertIn('solo la detección y la contención de Ryu', md)
            with open(os.path.join(tmp, 'evaluacion.json')) as f:
                d = json.load(f)['resumen']['deteccion']['global']
            self.assertEqual((d['FP'], d['VN']), (1, 0))



class AgenteConConfig(AgenteFalso):
    """Agente falso con /api/salud y /api/config (GET y PUT), que registra los cambios de configuración."""
    config = {'LLM_HABILITADO': True, 'CONTEXTO_HABILITADO': True}
    cambios = []

    def do_GET(self):
        if self.path == '/api/salud':
            return self._json({'ok': True})
        if self.path == '/api/config':
            return self._json(self.config)
        return super().do_GET()

    def do_PUT(self):
        cuerpo = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        type(self).cambios.append(cuerpo)
        self.config.update(cuerpo)
        self._json(self.config)

    def _json(self, cuerpo):
        datos = json.dumps(cuerpo).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(datos)


class TestCorrerEvaluacion(unittest.TestCase):
    def test_plan_de_accion_en_dry_run(self):
        with redirect_stdout(StringIO()) as out:
            correr_evaluacion.main(['--dry-run', '--agente-dir', '/no/existe', '--repeticiones', '2'])
        texto = out.getvalue()
        self.assertIn('# Plan de acción', texto)
        self.assertIn('- [ ] .env del agente', texto)
        self.assertIn('Corridas: 40', texto)   # 10 escenarios × 2 repeticiones × 2 series

    @unittest.skipIf(orquestador.agente_disponible() or os.geteuid() != 0, 'necesita el puerto 8081 libre y root')
    def test_flujo_completo_con_series_simuladas(self):
        srv = HTTPServer(('127.0.0.1', 8081), AgenteConConfig)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        corrida = {'escenario': 'A1', 'repeticion': 1, 'etiqueta': 'ataque', 'dificil': False,
                   'sospechosos': ['10.0.10.1'], 'metricas_previstas': ['M1', 'M2', 'M5'],
                   't_inicio': '2026-10-28T03:00:00Z', 't_fin': '2026-10-28T03:00:35Z', 'error': None, 'logs': {},
                   'bloqueados': [{'ip': '10.0.10.1', 'desde': '2026-10-28T03:00:12.400000Z'}],
                   'drop_en_switches': {'10.0.10.1': ['s1', 's2', 's3']}}
        originales = (orquestador.ejecutar, correr_evaluacion.verificaciones)

        with tempfile.TemporaryDirectory() as tmp:
            def ejecutar_falso(argv):
                bloque = argv[argv.index('--bloque') + 1]
                ruta = os.path.join(tmp, f'{bloque}.jsonl')
                with open(ruta, 'w') as f:
                    f.write(json.dumps({**corrida, 'corrida_id': bloque, 'bloque': bloque}) + '\n')
                return ruta

            orquestador.ejecutar = ejecutar_falso
            correr_evaluacion.verificaciones = lambda d: ([('todo', True)], {'AGENT_TOKEN': 'a', 'OPERADOR_TOKEN': 'op'})
            try:
                with redirect_stdout(StringIO()):
                    correr_evaluacion.main(['--salida', tmp, '--solo', 'A1', '--repeticiones', '1'])
            finally:
                orquestador.ejecutar, correr_evaluacion.verificaciones = originales
                srv.shutdown()
                srv.server_close()
            base = next(os.path.join(tmp, d) for d in os.listdir(tmp) if d.endswith('_objetivo3'))
            with open(os.path.join(base, 'informe', 'resumen.md')) as f:
                md = f.read()
            self.assertIn('## Cumplimiento del objetivo 3', md)
            self.assertIn('## LLM frente a reglas', md)
            self.assertTrue(os.path.exists(os.path.join(base, 'plan_de_accion.md')))
            self.assertTrue(os.path.exists(os.path.join(base, 'calificacion', 'plantilla_calificacion.csv')))
        # cada serie fija LLM_HABILITADO, el contexto se apaga y al final se restaura lo que había
        self.assertEqual(AgenteConConfig.cambios[0], {'CONTEXTO_HABILITADO': False})
        self.assertEqual([c.get('LLM_HABILITADO') for c in AgenteConConfig.cambios[1:3]], [True, False])
        self.assertEqual(AgenteConConfig.cambios[-1], {'LLM_HABILITADO': True, 'CONTEXTO_HABILITADO': True})


class TestPruebasEstadisticas(unittest.TestCase):
    def test_fisher(self):
        self.assertEqual(evaluar.fisher_exacto(8, 2, 1, 5), 0.035)    # R: fisher.test → 0.03497
        self.assertEqual(evaluar.fisher_exacto(3, 1, 1, 3), 0.4857)

    def test_mann_whitney(self):
        r = evaluar.mann_whitney([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])
        self.assertEqual((r['U'], r['p'], r['delta_cliff']), (0.0, 0.0122, -1.0))   # SciPy asintótico: 0.0122


if __name__ == '__main__':
    unittest.main()
