#!/usr/bin/env python3
"""
=============================================================================
CONTROLADOR RYU — PROYECTO DE GRADO
Universidad Católica de Colombia
Autores: Alejandro Salas Jurado / Sebastián Briceño Restrepo

Descripción:
  Aplicación Ryu con OpenFlow 1.3 que implementa 3 capas de operación:

  CAPA 1 — NORMAL:
    • MAC learning con aislamiento VLAN (OPS=10 / ADM=20)
    • Monitoreo silencioso de las 5 métricas OpenFlow
    • Período de gracia de 30s al arrancar

  CAPA 2 — SOSPECHOSO (puntaje 30-59):
    • Rate-limiting en puertos críticos del host sospechoso
    • Tráfico forzado a pasar por el controlador (no se corta)
    • Log detallado del comportamiento

  CAPA 3 — CRÍTICO (puntaje ≥ 60):
    • OFPFlowMod DROP prioridad 100 → host aislado de la red
    • Construcción y envío de payload JSON al agente LLM
    • El agente LLM responde con pasos a ejecutar + alertas

  Sistema de puntuación ponderada (justificado por likelihood ratio):
    M5 flujos east-west   → peso 40 (especificidad ~99.9% vs tráfico benigno)
    M3 SMB breve+volum.   → peso 35 (especificidad ~99.7% vs tráfico benigno)
    M1 escaneo de flujos  → peso 25 (puede ocurrir en tráfico legítimo intenso)
    M2 fan-out destinos   → peso 20 (puede ocurrir en servidores de actualización)
    M4 flood Packet-In    → peso 15 (puede tener causas no maliciosas)
    Puntaje 0-29  → NORMAL      | 30-59 → SOSPECHOSO | ≥60 → CRÍTICO

  Métricas implementadas:
    M1 — Tasa de nuevos flujos hacia puertos críticos  (Packet-In, ventana 30s)
    M2 — Fan-out de destinos únicos                   (Packet-In, ventana 30s)
    M3 — Duración corta + volumen alto SMB            (OFPFlowStatsReply)
    M4 — Tasa de Packet-In por host                   (EventOFPPacketIn, tiempo real)
    M5 — Flujos east-west en puertos crit.            (monitor + umbral)

  CAMBIOS v2:
    - M1/M2 migrados de polling OFPFlowStats → Packet-In en tiempo real
      (OVS instala flujos L2, no L3, así que el polling no ve ipv4_src)
    - M4 con cooldown de 60s entre alertas del mismo host
    - Score se resetea cada SCORE_RESET_SEC para no acumular indefinidamente
    - Forwarding L2 sin VLAN tag (Mininet sin 802.1Q explícito en hosts)

Uso:
    ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633

Dependencias:
    pip install ryu
    (urllib de stdlib — sin requests, compatible con Python 3.8)
=============================================================================
"""

import json
import os
import re
import time
import threading
import urllib.request
import urllib.error
import logging
from collections import defaultdict
from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, vlan
from ryu.lib import hub

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN — todos los parámetros ajustables están aquí
# ═══════════════════════════════════════════════════════════════════════════════

LOG_LEVEL        = logging.INFO
POLLING_INTERVAL = 10       # segundos entre ciclos de polling OFPFlowStats (M3)

# ── VLANs ─────────────────────────────────────────────────────────────────────
VLAN_OPS   = 10
VLAN_ADM   = 20
SUBNET_OPS = '10.0.10.'
SUBNET_ADM = '10.0.20.'

# ── Puertos críticos (movimiento lateral) ─────────────────────────────────────
CRITICAL_PORTS = {445, 135, 3389, 5985, 139}

# ── Umbrales de las 5 métricas ────────────────────────────────────────────────
THRESHOLD_M1_FLOWS_PER_30S = 20     # M1: nuevos flujos en 30s hacia puertos críticos
THRESHOLD_M2_UNIQUE_DSTS   = 8      # M2: destinos únicos en 30s
                                    # Justificación: red de 10 hosts/VLAN (PyME colombiana típica,
                                    # Ley 905/2004, BBVA Research 2024). Ryuk contacta 9/9 hosts;
                                    # umbral 8 detecta 89% del escaneo sin FP por tráfico legítimo.
THRESHOLD_M3_DURATION_SEC  = 5      # M3: duración máxima del flujo SMB (segundos)
THRESHOLD_M3_BYTES         = 512000 # M3: volumen mínimo del flujo SMB (~500 KB)
THRESHOLD_M4_PACKET_IN_MIN = 200    # M4: Packet-In por minuto desde un host
THRESHOLD_M5_COUNT         = 5      # M5: flujos W2W distintos en puertos críticos

# ── Ventanas temporales ───────────────────────────────────────────────────────
WINDOW_M1_M2_SEC = 30   # ventana deslizante para M1 y M2
WINDOW_M4_SEC    = 60   # ventana deslizante para M4

# ── Cooldowns ─────────────────────────────────────────────────────────────────
M4_ALERT_COOLDOWN_SEC = 60   # mínimo tiempo entre alertas M4 del mismo host
M1_ALERT_COOLDOWN_SEC = 10   # mínimo tiempo entre alertas M1 del mismo host
M2_ALERT_COOLDOWN_SEC = 10   # mínimo tiempo entre alertas M2 del mismo host
SCORE_RESET_SEC       = 300  # resetear score después de 5 min sin nueva métrica

# ── Sistema de puntuación ponderada ──────────────────────────────────────────
METRIC_WEIGHTS = {
    'M5': 40,
    'M3': 35,
    'M1': 25,
    'M2': 20,
    'M4': 15,
}

SCORE_NORMAL     = 0
SCORE_SUSPICIOUS = 30
SCORE_CRITICAL   = 60

# ── Período de gracia al arrancar ─────────────────────────────────────────────
STARTUP_GRACE_SEC = 30

# ── Destino del payload JSON (agente LLM) ─────────────────────────────────────
AGENT_URL     = 'http://localhost:8081/api/alertas'
AGENT_TIMEOUT = 5       # el agente responde en < 300 ms; el análisis ocurre después
AGENT_ENABLED = True    # True cuando el agente LLM esté corriendo
AGENT_TOKEN   = os.environ.get('AGENT_TOKEN', '')

# ── Rate-limit: parámetros de la Capa 2 ──────────────────────────────────────
RATE_LIMIT_IDLE_TIMEOUT = 60
RATE_LIMIT_HARD_TIMEOUT = 120

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
logger = logging.getLogger('RyuSDN')


# ═══════════════════════════════════════════════════════════════════════════════
class SDNRansomwareDetector(app_manager.RyuApp):
    """
    Controlador SDN con detección de movimiento lateral en 3 capas.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tabla de MACs: {dpid: {mac: puerto}}
        self.mac_to_port = defaultdict(dict)

        # Datapaths registrados: {dpid: datapath}
        self.datapaths = {}

        # IPs de workstations conocidas
        self.workstation_ips = set()

        # Bitácora de tráfico por host
        # flows: lista de (ip_dst, timestamp, tp_dst) — para M1/M2
        # packet_in_times: timestamps de Packet-In — para M4
        # east_west: set de (ip_dst, tp_dst) W2W — para M5
        self.host_flow_log = defaultdict(lambda: {
            'flows':            [],
            'packet_in_times':  [],
            'east_west':        set(),
        })

        # Estado de alerta por host
        self.host_alert_state = defaultdict(lambda: {
            'level':             'NORMAL',
            'metrics_triggered': set(),
            'score':             0,
            'last_alert':        0,      # timestamp última alerta (cooldown M4)
            'last_metric_time':  0,      # para reset de score
        })

        # Snapshot de valores numéricos al momento del disparo
        self.metric_snapshot = defaultdict(dict)

        # Hosts con DROP instalado
        self.blocked_hosts = {}   # {ip: {'dpids': [int, ...], 'desde': 'ISO-8601Z'}}

        # Umbrales editables en tiempo de ejecución (mismos valores por defecto)
        self.umbrales = {
            'M1': THRESHOLD_M1_FLOWS_PER_30S,            # 20
            'M2': THRESHOLD_M2_UNIQUE_DSTS,              # 8
            'M3_DURACION_S': THRESHOLD_M3_DURATION_SEC,  # 5
            'M3_BYTES': THRESHOLD_M3_BYTES,              # 512000
            'M4': THRESHOLD_M4_PACKET_IN_MIN,            # 200
            'M5': THRESHOLD_M5_COUNT,                    # 5
            'SCORE_SOSPECHOSO': SCORE_SUSPICIOUS,        # 30
            'SCORE_CRITICO': SCORE_CRITICAL,             # 60
        }

        # Tiempo de arranque
        self._start_time = time.time()

        # Hilo de polling (solo para M3 ahora)
        self._polling_thread = hub.spawn(self._polling_loop)

        logger.info('=' * 60)
        logger.info('  Controlador SDN — 3 capas de detección activas  v2')
        logger.info(f'  Período de gracia: {STARTUP_GRACE_SEC}s')
        logger.info(f'  Puntaje SOSPECHOSO: >={self.umbrales["SCORE_SOSPECHOSO"]} puntos (rate-limit)')
        logger.info(f'  Puntaje CRITICO:    >={self.umbrales["SCORE_CRITICO"]} puntos (DROP + LLM)')
        logger.info(f'  Pesos: M5={METRIC_WEIGHTS["M5"]} M3={METRIC_WEIGHTS["M3"]} '
                    f'M1={METRIC_WEIGHTS["M1"]} M2={METRIC_WEIGHTS["M2"]} M4={METRIC_WEIGHTS["M4"]}')
        logger.info(f'  M1/M2: Packet-In en tiempo real (ventana {WINDOW_M1_M2_SEC}s)')
        logger.info(f'  M4 cooldown: {M4_ALERT_COOLDOWN_SEC}s entre alertas')
        logger.info(f'  Agente LLM: {"HABILITADO" if AGENT_ENABLED else "DESHABILITADO (modo log)"}')
        logger.info('=' * 60)
        if AGENT_ENABLED and not AGENT_TOKEN:
            logger.error('[AGENTE] AGENT_TOKEN vacío: el agente rechazará las alertas (401)')

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA BASE — CONEXIÓN DE SWITCHES
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.datapaths[dpid] = datapath
        logger.info(f'[SWITCH] Conectado: DPID={dpid:#018x}')

        # Regla table-miss (prioridad 0): todo sube al controlador
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        # Reglas de monitoreo M5
        self._install_m5_monitor_rules(datapath)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 1 — PROCESAMIENTO NORMAL (Packet-In)
    # ═══════════════════════════════════════════════════════════════════════════
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # Ignorar LLDP y STP
        if eth_pkt.ethertype in (0x88cc, 0x8942):
            return

        dst_mac  = eth_pkt.dst
        src_mac  = eth_pkt.src
        vlan_pkt = pkt.get_protocol(vlan.vlan)
        vlan_id  = vlan_pkt.vid if vlan_pkt else None
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        src_ip = ip_pkt.src if ip_pkt else None
        dst_ip = ip_pkt.dst if ip_pkt else None
        tp_dst = (tcp_pkt.dst_port if tcp_pkt else
                  udp_pkt.dst_port if udp_pkt else None)

        # ── MAC learning ──────────────────────────────────────────────────────
        self.mac_to_port[dpid][src_mac] = in_port

        # ── Registrar IP de workstation ───────────────────────────────────────
        if src_ip and (src_ip.startswith(SUBNET_OPS) or
                       src_ip.startswith(SUBNET_ADM)):
            self.workstation_ips.add(src_ip)

        # ── Período de gracia ─────────────────────────────────────────────────
        in_grace = (time.time() - self._start_time) < STARTUP_GRACE_SEC

        if src_ip and not in_grace and src_ip not in self.blocked_hosts:

            now = time.time()

            # ── M4: contar Packet-In por host ─────────────────────────────────
            self.host_flow_log[src_ip]['packet_in_times'].append(now)
            self._evaluate_m4(src_ip, datapath)

            # ── M1/M2: registrar flujos hacia puertos críticos ────────────────
            if dst_ip and tp_dst and tp_dst in CRITICAL_PORTS:
                self.host_flow_log[src_ip]['flows'].append(
                    (dst_ip, now, tp_dst)
                )
                self._evaluate_m1_m2(src_ip, datapath)

            # ── M5: flujos east-west ──────────────────────────────────────────
            if (dst_ip and tp_dst
                    and src_ip in self.workstation_ips
                    and dst_ip in self.workstation_ips
                    and tp_dst in CRITICAL_PORTS):

                ew_log = self.host_flow_log[src_ip]['east_west']
                ew_log.add((dst_ip, tp_dst))
                ew_count = len(ew_log)

                logger.debug(f'[M5] {src_ip}->{dst_ip}:{tp_dst} '
                             f'W2W acumulados: {ew_count}/{self.umbrales["M5"]}')

                if ew_count >= self.umbrales['M5']:
                    self._trigger_metric(
                        src_ip, 'M5', datapath, in_port,
                        msg=f'M5: {ew_count} flujos W2W en puertos criticos '
                            f'>= umbral {self.umbrales["M5"]}'
                    )

        # ── Aislamiento inter-VLAN ────────────────────────────────────────────
        if src_ip and dst_ip:
            src_ops = src_ip.startswith(SUBNET_OPS)
            dst_ops = dst_ip.startswith(SUBNET_OPS)
            if src_ops != dst_ops:
                logger.debug(f'[VLAN] Bloqueado inter-VLAN: {src_ip}->{dst_ip}')
                return

        # ── Forwarding L2 ─────────────────────────────────────────────────────
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Instalar flujo L2 si conocemos el puerto destino
        if (out_port != ofproto.OFPP_FLOOD
                and (src_ip is None or src_ip not in self.blocked_hosts)):
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self._add_flow(datapath, priority=1, match=match,
                           actions=actions,
                           idle_timeout=30, hard_timeout=60)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        datapath.send_msg(out)

    # ═══════════════════════════════════════════════════════════════════════════
    # EVALUACIÓN M1 / M2 — ventana deslizante en Packet-In
    # ═══════════════════════════════════════════════════════════════════════════
    def _evaluate_m1_m2(self, src_ip, datapath):
        """
        Evalúa M1 y M2 usando el log de flujos registrado en Packet-In.
        Solo cuenta flujos hacia CRITICAL_PORTS en los últimos WINDOW_M1_M2_SEC.
        """
        now    = time.time()
        cutoff = now - WINDOW_M1_M2_SEC

        # Limpiar entradas antiguas
        flows = self.host_flow_log[src_ip]['flows']
        flows[:] = [f for f in flows if f[1] > cutoff]

        m1_val = len(flows)
        m2_val = len({f[0] for f in flows})

        if m1_val > 0:
            logger.debug(f'[M1/M2] {src_ip} — flujos={m1_val} dsts={m2_val} '
                         f'en ventana {WINDOW_M1_M2_SEC}s')

        now   = time.time()
        state = self.host_alert_state[src_ip]

        if m1_val > self.umbrales['M1']:
            last_m1 = state.get('last_m1_alert', 0)
            if now - last_m1 >= M1_ALERT_COOLDOWN_SEC:
                state['last_m1_alert'] = now
                self._trigger_metric(
                    src_ip, 'M1', datapath, None,
                    msg=f'M1: {m1_val} flujos nuevos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {self.umbrales["M1"]}'
                )
        if m2_val > self.umbrales['M2']:
            last_m2 = state.get('last_m2_alert', 0)
            if now - last_m2 >= M2_ALERT_COOLDOWN_SEC:
                state['last_m2_alert'] = now
                self._trigger_metric(
                    src_ip, 'M2', datapath, None,
                    msg=f'M2: {m2_val} destinos unicos en {WINDOW_M1_M2_SEC}s '
                        f'> umbral {self.umbrales["M2"]}'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # EVALUACIÓN M4 — con cooldown
    # ═══════════════════════════════════════════════════════════════════════════
    def _evaluate_m4(self, src_ip, datapath):
        """Evalúa M4 con ventana deslizante y cooldown entre alertas."""
        now    = time.time()
        cutoff = now - WINDOW_M4_SEC

        log = self.host_flow_log[src_ip]
        log['packet_in_times'] = [t for t in log['packet_in_times'] if t > cutoff]
        rate = len(log['packet_in_times']) * (60 / WINDOW_M4_SEC)

        if rate > self.umbrales['M4']:
            state = self.host_alert_state[src_ip]
            last  = state.get('last_alert', 0)

            if now - last >= M4_ALERT_COOLDOWN_SEC:
                state['last_alert'] = now
                self._trigger_metric(
                    src_ip, 'M4', datapath, None,
                    msg=f'M4: {rate:.0f} Packet-In/min '
                        f'> umbral {self.umbrales["M4"]}'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # POLLING — solo M3 (requiere byte_count de OFPFlowStatsReply)
    # ═══════════════════════════════════════════════════════════════════════════
    def _polling_loop(self):
        hub.sleep(STARTUP_GRACE_SEC + 5)
        logger.info(f'[POLLING] Iniciado cada {POLLING_INTERVAL}s (solo M3)')
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                self._request_flow_stats(datapath)
            hub.sleep(POLLING_INTERVAL)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(
            datapath, flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0, cookie_mask=0,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Evalúa solo M3 (SMB breve y voluminoso) con datos de OVS."""
        body     = ev.msg.body
        datapath = ev.msg.datapath

        flows_by_src = defaultdict(list)
        for stat in body:
            m      = stat.match
            src_ip = m.get('ipv4_src')
            dst_ip = m.get('ipv4_dst')
            tp_dst = m.get('tcp_dst') or m.get('udp_dst')
            if src_ip and dst_ip:
                flows_by_src[src_ip].append({
                    'dst_ip':   dst_ip,
                    'tp_dst':   tp_dst,
                    'duration': stat.duration_sec,
                    'bytes':    stat.byte_count,
                })

        for src_ip, flows in flows_by_src.items():
            if src_ip in self.blocked_hosts:
                continue

            # M3: flujo SMB breve y voluminoso
            m3_flow = next((
                f for f in flows
                if f['tp_dst'] == 445
                and f['duration'] < self.umbrales['M3_DURACION_S']
                and f['bytes']    > self.umbrales['M3_BYTES']
            ), None)

            if m3_flow:
                self.metric_snapshot[src_ip]['M3_duration'] = m3_flow['duration']
                self.metric_snapshot[src_ip]['M3_bytes']    = m3_flow['bytes']
                self._trigger_metric(
                    src_ip, 'M3', datapath, None,
                    msg=f'M3: flujo SMB <{self.umbrales["M3_DURACION_S"]}s '
                        f'y >{self.umbrales["M3_BYTES"]}B detectado '
                        f'({m3_flow["bytes"]}B en {m3_flow["duration"]}s)'
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # MOTOR DE ALERTAS — decide la capa de respuesta
    # ═══════════════════════════════════════════════════════════════════════════
    def _trigger_metric(self, src_ip, metric_id, datapath, in_port, msg=''):
        """
        Sistema de puntuación ponderada.
        Cada métrica nueva suma su peso. El score se resetea si pasan
        SCORE_RESET_SEC sin que se dispare ninguna métrica nueva.
        """
        elapsed = time.time() - self._start_time
        if elapsed < STARTUP_GRACE_SEC:
            remaining = int(STARTUP_GRACE_SEC - elapsed)
            logger.debug(f'[GRACIA] {src_ip}/{metric_id} ignorada '
                         f'({remaining}s restantes)')
            return

        state = self.host_alert_state[src_ip]
        now   = time.time()

        # Reset de score si pasó mucho tiempo sin nuevas métricas
        if (state['last_metric_time'] > 0
                and now - state['last_metric_time'] > SCORE_RESET_SEC
                and state['level'] == 'NORMAL'):
            logger.info(f'[SCORE] {src_ip} — score reseteado '
                        f'(>{SCORE_RESET_SEC}s sin actividad)')
            state['metrics_triggered'] = set()
            state['score']             = 0

        state['last_metric_time'] = now
        peso = METRIC_WEIGHTS.get(metric_id, 0)

        # Solo sumar peso si es la primera vez que se dispara esta métrica
        es_nueva = metric_id not in state['metrics_triggered']
        if es_nueva:
            state['metrics_triggered'].add(metric_id)
            state['score'] += peso

        score = state['score']

        # Guardar valor numérico para el JSON (el texto después de "Mx:")
        cuerpo = msg.split(':', 1)[1] if ':' in msg else msg
        nums = re.findall(r'\d+\.?\d*', cuerpo)
        if nums:
            self.metric_snapshot[src_ip][metric_id] = float(nums[0])

        logger.warning(
            f'[{metric_id}] {src_ip} — {msg} '
            f'| peso={peso} | puntaje={score} '
            f'| metricas={sorted(state["metrics_triggered"])}'
        )

        prev_level = state['level']

        # ── CAPA 2: SOSPECHOSO ────────────────────────────────────────────────
        if self.umbrales['SCORE_SOSPECHOSO'] <= score < self.umbrales['SCORE_CRITICO']:
            if prev_level == 'NORMAL':
                state['level'] = 'SOSPECHOSO'
                logger.warning(
                    f'[CAPA 2] {src_ip} -> SOSPECHOSO '
                    f'(puntaje={score}, '
                    f'metricas={sorted(state["metrics_triggered"])}) '
                    f'— aplicando rate-limit'
                )
                dp = datapath or next(iter(self.datapaths.values()), None)
                if dp:
                    self._apply_rate_limit(dp, src_ip)

        # ── CAPA 3: CRITICO ───────────────────────────────────────────────────
        elif score >= self.umbrales['SCORE_CRITICO']:
            state['level'] = 'CRITICO'
            if src_ip not in self.blocked_hosts:
                logger.critical(
                    f'[CAPA 3] {src_ip} -> CRITICO '
                    f'(puntaje={score}, '
                    f'metricas={sorted(state["metrics_triggered"])}) '
                    f'— DROP + escalando al agente LLM'
                )
                dp = datapath or next(iter(self.datapaths.values()), None)
                if dp:
                    self._block_host(dp, src_ip)
                self._send_json_alert(src_ip, state, dp)

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 2 — RATE-LIMIT
    # ═══════════════════════════════════════════════════════════════════════════
    def _apply_rate_limit(self, datapath, src_ip):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instaladas = 0
        for port in CRITICAL_PORTS:
            try:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ip_proto=6,
                    tcp_dst=port,
                )
                actions = [parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
                )]
                self._add_flow(
                    datapath, priority=20, match=match, actions=actions,
                    idle_timeout=RATE_LIMIT_IDLE_TIMEOUT,
                    hard_timeout=RATE_LIMIT_HARD_TIMEOUT,
                )
                instaladas += 1
            except Exception as e:
                logger.debug(f'[RATE-LIMIT] Error en puerto {port}: {e}')

        logger.warning(f'[CAPA 2] Rate-limit aplicado a {src_ip} '
                       f'en {instaladas} puertos criticos '
                       f'(expira en {RATE_LIMIT_IDLE_TIMEOUT}s)')

    # ═══════════════════════════════════════════════════════════════════════════
    # CAPA 3 — DROP + JSON AL AGENTE LLM
    # ═══════════════════════════════════════════════════════════════════════════
    def _block_host(self, datapath, src_ip):
        """DROP prioridad 100 en TODOS los switches conectados."""
        dpids = []
        for dpid, dp in list(self.datapaths.items()):
            parser = dp.ofproto_parser
            match  = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            self._add_flow(dp, priority=100, match=match, actions=[],
                           idle_timeout=0, hard_timeout=0)
            dpids.append(dpid)
        self.blocked_hosts[src_ip] = {
            'dpids': dpids,
            'desde': datetime.utcnow().isoformat() + 'Z',
        }
        logger.critical(f'[CAPA 3] {src_ip} — DROP en {len(dpids)} switch(es)')

    def _send_json_alert(self, src_ip, state, datapath):
        snap      = self.metric_snapshot.get(src_ip, {})
        log       = self.host_flow_log.get(src_ip, {})
        now       = time.time()
        cutoff    = now - WINDOW_M1_M2_SEC
        triggered = sorted(state['metrics_triggered'])

        recent_flows = [f for f in log.get('flows', []) if f[1] > cutoff]
        m1_val = snap.get('M1', len(recent_flows))
        m2_val = snap.get('M2', len({f[0] for f in recent_flows}))
        pkt_times = [t for t in log.get('packet_in_times', [])
                     if t > now - WINDOW_M4_SEC]
        m4_val = snap.get('M4', round(len(pkt_times) * (60 / WINDOW_M4_SEC), 1))

        payload = {
            'timestamp':           datetime.utcnow().isoformat() + 'Z',
            'alerta_nivel':        'CRITICO',
            'host_origen':         src_ip,
            'dpid_switch':         f'{datapath.id:#018x}' if datapath else 'unknown',
            'contexto_topologico': self._get_topology_context(src_ip),
            'metricas': {
                'M1_nuevos_flujos_por_30s':   m1_val,
                'M2_destinos_unicos_por_30s': m2_val,
                'M3_smb_anomalo':             'M3' in triggered,
                'M3_duracion_seg':            snap.get('M3_duration', None),
                'M3_bytes':                   snap.get('M3_bytes', None),
                'M4_packet_in_por_min':       m4_val,
                'M5_flujos_east_west':        'M5' in triggered,
                'M5_count':                   snap.get('M5', len(log.get('east_west', set()))),
            },
            'puntaje_total':       state['score'],
            'puntaje_maximo':      sum(METRIC_WEIGHTS.values()),
            'pesos_metricas':      {m: METRIC_WEIGHTS[m]
                                    for m in triggered if m in METRIC_WEIGHTS},
            'umbrales_superados':  triggered,
            'ioc_activados':       self._map_ioc(triggered),
            'accion_ryu_previa':   f'OFPFlowMod DROP prioridad 100 — {src_ip} aislado',
            'solicitud_al_agente': (
                'Analiza el incidente. Responde SOLO con un JSON con estos campos: '
                'veredicto (confirmado/falso_positivo/indeterminado/ya_contenido), '
                'severidad (critica/alta/media), '
                'confianza (0-100), '
                'nivel_autonomia (1/2/3), '
                'acciones_automaticas (lista), '
                'acciones_pendientes_aprobacion (lista), '
                'hosts_en_riesgo (lista de IPs), '
                'mensaje_telegram (texto para el operador SOC), '
                'recomendaciones_forenses (lista), '
                'actualizar_estado_red ({nivel_alerta_red: NORMAL|MEDIO|ALTO|CRITICO}).'
            ),
        }

        logger.info(f'[CAPA 3] Payload JSON para {src_ip}:\n'
                    f'{json.dumps(payload, indent=2, ensure_ascii=False)}')

        if AGENT_ENABLED:
            thread = threading.Thread(
                target=self._post_to_agent,
                args=(payload,),
                daemon=True,
            )
            thread.start()
        else:
            logger.info('[AGENTE] AGENT_ENABLED=False — '
                        'JSON registrado en log, no enviado al agente.')

    def _post_to_agent(self, payload):
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req  = urllib.request.Request(
            AGENT_URL,
            data=data,
            headers={'Content-Type': 'application/json',
                     'X-Agent-Token': AGENT_TOKEN},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=AGENT_TIMEOUT) as resp:
                body   = resp.read().decode('utf-8')
                status = resp.status
                logger.info(f'[AGENTE] HTTP {status} — respuesta recibida')
                try:
                    respuesta = json.loads(body)
                    self._ejecutar_respuesta_agente(payload['host_origen'], respuesta)
                except json.JSONDecodeError:
                    logger.warning(f'[AGENTE] Respuesta no JSON: {body[:200]}')
        except urllib.error.URLError:
            logger.warning(f'[AGENTE] No disponible en {AGENT_URL} '
                           '— JSON quedó en log')
        except Exception as e:
            logger.error(f'[AGENTE] Error inesperado: {e}')

    def _ejecutar_respuesta_agente(self, src_ip, respuesta):
        veredicto = respuesta.get('veredicto', 'indeterminado')
        confianza = respuesta.get('confianza', 0)
        nivel     = respuesta.get('nivel_autonomia', 1)
        acciones_a = respuesta.get('acciones_automaticas', [])
        acciones_p = respuesta.get('acciones_pendientes_aprobacion', [])
        forenses   = respuesta.get('recomendaciones_forenses', [])
        nivel_red  = respuesta.get('actualizar_estado_red', {}).get('nivel_alerta_red', '')

        logger.info(f'[AGENTE] Veredicto:  {veredicto} ({confianza}% confianza)')
        logger.info(f'[AGENTE] Nivel HITL: {nivel}')
        logger.info(f'[AGENTE] Auto:       {acciones_a}')
        logger.info(f'[AGENTE] Pendientes: {acciones_p}')
        if nivel_red:
            logger.info(f'[AGENTE] Nivel red:  {nivel_red}')
        if forenses:
            logger.info(f'[AGENTE] Forenses:   {forenses}')

        if veredicto in ('confirmado', 'ya_contenido'):
            logger.info(f'[AGENTE] Ataque {veredicto} — DROP mantenido para {src_ip}')
        elif veredicto == 'indeterminado':
            logger.warning(f'[AGENTE] Indeterminado para {src_ip} '
                           '— DROP mantenido hasta revision manual')
        else:
            logger.warning(f'[AGENTE] Veredicto desconocido: {veredicto}')

    # ═══════════════════════════════════════════════════════════════════════════
    # MONITOR M5 — reglas de observación east-west
    # ═══════════════════════════════════════════════════════════════════════════
    def _install_m5_monitor_rules(self, datapath):
        """
        Instala reglas de monitoreo W2W en puertos críticos.
        Prioridad 10 — el paquete sube al controlador Y se reenvía normalmente.
        """
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid    = datapath.id
        count   = 0

        for tp_dst in CRITICAL_PORTS:
            for subred in (SUBNET_OPS, SUBNET_ADM):
                for src_s in range(1, 6):
                    for dst_s in range(1, 6):
                        if src_s == dst_s:
                            continue
                        try:
                            match = parser.OFPMatch(
                                eth_type=0x0800,
                                ipv4_src=f'{subred}{src_s}',
                                ipv4_dst=f'{subred}{dst_s}',
                                ip_proto=6,
                                tcp_dst=tp_dst,
                            )
                            actions = [
                                parser.OFPActionOutput(
                                    ofproto.OFPP_CONTROLLER,
                                    ofproto.OFPCML_NO_BUFFER
                                ),
                                parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                            ]
                            self._add_flow(
                                datapath, priority=10,
                                match=match, actions=actions,
                                idle_timeout=0, hard_timeout=0,
                            )
                            count += 1
                        except Exception:
                            pass

        logger.info(f'[M5] {count} reglas de monitoreo W2W instaladas '
                    f'en DPID={dpid:#018x}')

    # ═══════════════════════════════════════════════════════════════════════════
    # UTILIDADES
    # ═══════════════════════════════════════════════════════════════════════════
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, table_id=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = (
            [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            if actions else
            [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        )
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            table_id=table_id,
        )
        datapath.send_msg(mod)

    def _map_ioc(self, triggered):
        t = set(triggered)
        iocs = []
        if {'M1', 'M2'}.issubset(t): iocs.append('IOC-01')
        if 'M3' in t:                iocs.append('IOC-02')
        if 'M4' in t:                iocs.append('IOC-03')
        if 'M5' in t:                iocs.append('IOC-04')
        if {'M5', 'M1'}.issubset(t): iocs.append('IOC-07')
        score = sum(METRIC_WEIGHTS.get(m, 0) for m in t)
        if score >= self.umbrales['SCORE_CRITICO']:  iocs.append('IOC-05')
        return sorted(set(iocs))

    def _get_topology_context(self, src_ip):
        if src_ip.startswith(SUBNET_OPS):
            return f'VLAN OPS (ID={VLAN_OPS}), subred {SUBNET_OPS}0/24'
        if src_ip.startswith(SUBNET_ADM):
            return f'VLAN ADM (ID={VLAN_ADM}), subred {SUBNET_ADM}0/24'
        return 'subred desconocida'
