# Ajustes a Ryu-IA para integrarse con SDN-Agent v2

**Para:** Sebastián · **De:** Alejandro · **Archivo:** `ryu_controller.py` del repo `sbriceno1379/RYU_IA` (versión v2 con puntaje ponderado, commit 0c434ea)
**Regla general:** ningún cambio toca la lógica de detección M1–M5, el puntaje ponderado ni sus valores por defecto.

| ID | Qué | Prioridad | Esfuerzo |
|---|---|---|---|
| A0 | Corregir los valores de las métricas en la alerta (defecto) | **Obligatorio, urgente** | 5 min |
| A1 | Enviar alertas al agente (puerto, ruta, token) | **Obligatorio** | 10 min |
| A2 | Quitar el desbloqueo automático | **Obligatorio** | 5 min |
| A3 | Bloquear en todos los switches y recordar dónde | **Obligatorio** | 20 min |
| A4 | Umbrales editables en tiempo de ejecución | **Obligatorio** | 20 min |
| A5 | API REST (estado, bloqueados, desbloquear, umbrales) | **Obligatorio** | 1–2 h |
| A6 | Modo cuarentena (para autonomía acotada del agente) | Opcional | 1–2 h |
| — | Lo que NO se debe cambiar | **Leer** | — |

---

## A0. Corregir los valores de las métricas — OBLIGATORIO Y URGENTE

**Defecto:** en `_trigger_metric` el valor se extrae con `re.findall(r'\d+\.?\d*', msg)` y se toma el **primer** número. Pero todos los mensajes empiezan con el nombre de la métrica (`'M1: 24 flujos...'`, `'M2: 9 destinos...'`, `'M5: 8 flujos...'`), así que el primer número es el **dígito del nombre**: se guarda `M1=1.0`, `M2=2.0`, `M4=4.0`, `M5=5.0` en vez de 24, 9, 250 y 8.

**Consecuencia:** cada alerta real llega al agente con valores falsos (por ejemplo `M1_nuevos_flujos_por_30s: 1.0` aunque hubo 24 flujos). El LLM y las reglas explican con datos equivocados, y la evaluación de la tesis queda invalidada. El defecto también estaba en la versión anterior del controlador.

**Corrección** (en `_trigger_metric`, reemplazar las 3 líneas del snapshot):

```python
# Guardar valor numérico para el JSON (el texto después de "Mx:")
cuerpo = msg.split(':', 1)[1] if ':' in msg else msg
nums = re.findall(r'\d+\.?\d*', cuerpo)
if nums:
    self.metric_snapshot[src_ip][metric_id] = float(nums[0])
```

**Verificación:** con `ataque_completo.py`, el log `[CAPA 3] Payload JSON` debe mostrar `M1_nuevos_flujos_por_30s` mayor que 20 y `M2_destinos_unicos_por_30s` mayor que 8 (los umbrales superados), no 1.0 ni 2.0.

---

## A1. Enviar alertas al agente — OBLIGATORIO

Hoy (líneas ~130-132) las alertas van a `localhost:8081/alert` con `AGENT_ENABLED = True`, `AGENT_TIMEOUT = 35` y sin autenticación. El puerto ya es el correcto; faltan la ruta y el token.

```python
import os   # agregar arriba, junto a los demás imports

AGENT_URL     = 'http://localhost:8081/api/alertas'   # antes: 8081/alert
AGENT_TIMEOUT = 5    # antes 35: el agente responde en < 300 ms; el análisis ocurre después
AGENT_ENABLED = True
AGENT_TOKEN   = os.environ.get('AGENT_TOKEN', '')
```

En `_post_to_agent`, agregar el encabezado:

```python
req = urllib.request.Request(
    AGENT_URL,
    data=data,
    headers={'Content-Type': 'application/json',
             'X-Agent-Token': AGENT_TOKEN},
    method='POST',
)
```

Y al arrancar, advertir si falta el token (en `__init__`, después de los logs actuales):

```python
if AGENT_ENABLED and not AGENT_TOKEN:
    logger.error('[AGENTE] AGENT_TOKEN vacío: el agente rechazará las alertas (401)')
```

**Por qué:** el agente recibe las alertas en `/api/alertas` y rechaza las que no traen token. No hace falta esperar 35 s: el agente responde de inmediato y analiza en segundo plano.

**Ojo con `servidor_json.py`:** usa el mismo puerto 8081. No lo ejecutes al mismo tiempo que el agente.
**El token** te lo paso por un canal privado. Se exporta antes de arrancar: `export AGENT_TOKEN=...`. Nunca va en el código ni en el repo.

**Respuesta que vas a recibir** del agente (en menos de 300 ms; el análisis ocurre después):
```json
{"estado": "recibido", "incidente_id": 17, "acciones_ryu": ["mantener_bloqueo"]}
```

---

## A2. Quitar el desbloqueo automático — OBLIGATORIO

En `_ejecutar_respuesta_agente` (línea ~695) **eliminar** el bloque que libera el host cuando el agente dice falso positivo:

```python
# ELIMINAR COMPLETO:
if veredicto == 'falso_positivo' and confianza >= 85:
    ...
    self.blocked_hosts.discard(src_ip)
    self.host_alert_state[src_ip]['level'] = 'NORMAL'
    ...
```

Además de ir contra el diseño, ese bloque deja un estado inconsistente: saca la IP de `blocked_hosts`, pero la regla DROP sigue instalada en el switch.

La función queda solo registrando en el log lo que responde el agente. El agente v2 responde `{"estado": "recibido", "incidente_id": N, "acciones_ryu": ["mantener_bloqueo"]}`: no envía `veredicto`, así que hoy el código lo trata como "indeterminado" y mantiene el DROP. Aun así, el bloque debe eliminarse para que ninguna respuesta futura pueda desbloquear.

**Por qué:** decisión de diseño de la tesis. Ryu decide el bloqueo; solo un humano desbloquea, desde el panel y a través de A5. Si el LLM se equivoca o es manipulado, no puede liberar a un atacante.

---

## A3. Bloquear en todos los switches y recordar dónde — OBLIGATORIO

**Problema actual:** `_block_host` instala el DROP en **un solo switch**. Cuando la métrica viene sin `datapath` (M1, M2 y M3 desde el polling usan el del reply; M4 recibe uno cualquiera), `_trigger_metric` usa `next(iter(self.datapaths.values()))`: **el primer switch registrado, que puede no ser el del host.** La topología actual tiene **3 switches** (s1, s2, s3; `topology_project.py`), así que esto pasa de verdad: el host podría seguir comunicándose por otro switch. Además, `blocked_hosts` es un `set` y no guarda dónde ni cuándo se bloqueó, información necesaria para desbloquear.

**Cambio:**

```python
# En __init__: reemplazar  self.blocked_hosts = set()  por:
self.blocked_hosts = {}   # {ip: {'dpids': [int, ...], 'desde': 'ISO-8601Z'}}
```

```python
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
```

Todos los `src_ip in self.blocked_hosts` y `not in self.blocked_hosts` del archivo **siguen funcionando igual** con un diccionario. Solo hay que cambiar `self.blocked_hosts.discard(...)` y `self.blocked_hosts.add(...)`, si quedan, por `pop(ip, None)` y la asignación de arriba.

---

## A4. Umbrales editables en tiempo de ejecución — OBLIGATORIO

**Problema actual:** los umbrales y el puntaje son constantes del módulo (`THRESHOLD_*`, `SCORE_SUSPICIOUS`, `SCORE_CRITICAL`). Una API no puede cambiarlos de forma limpia.

**Cambio:** en `__init__`, copiarlos a un diccionario de la instancia con **los mismos valores por defecto que tiene hoy el código**:

```python
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
```

Y reemplazar cada uso de esas constantes **dentro de los métodos** por `self.umbrales['...']`: `_evaluate_m1_m2` (M1, M2), `flow_stats_reply_handler` (M3), `_evaluate_m4` (M4), `packet_in_handler` (M5), `_trigger_metric` y `_map_ioc` (SCORE_*). Los textos de los logs también deben usar el valor del diccionario.

Los **pesos** (`METRIC_WEIGHTS`) quedan como constantes: no se exponen para edición.

## A5. API REST mínima — OBLIGATORIO

Con el WSGI que ya trae Ryu (`ryu.app.wsgi`), en el puerto 8080. **Todas** las rutas exigen el encabezado `X-Agent-Token` (401 si falta o no coincide).

| Método | Ruta | Respuesta 200 | Errores |
|---|---|---|---|
| GET | `/ryu/estado` | `{"switches": ["0x...1"], "hosts_bloqueados": 1, "umbrales": {...}, "pesos": {"M5": 40, ...}, "version": "2.0"}` | 401 |
| GET | `/ryu/hosts/bloqueados` | `[{"ip": "10.0.10.3", "dpid": "0x0000000000000001", "desde": "2026-10-10T20:31:05Z"}]` (un elemento por IP; `dpid` = primero de la lista) | 401 |
| POST | `/ryu/hosts/{ip}/desbloquear` | `{"ok": true, "ip": "10.0.10.3", "reglas_borradas": 2}` | 401, 404 si no estaba bloqueado |
| GET | `/ryu/umbrales` | el diccionario `self.umbrales` (M1, M2, M3_DURACION_S, M3_BYTES, M4, M5, SCORE_SOSPECHOSO, SCORE_CRITICO) | 401 |
| PUT | `/ryu/umbrales` | cuerpo parcial, ej. `{"M2": 10}`; devuelve los vigentes | 401; 422 si una clave no existe o el valor no es entero > 0 |

**Esqueleto** (al final del archivo y en la clase principal):

```python
from ryu.app.wsgi import ControllerBase, WSGIApplication, route, Response
import ipaddress

API_INSTANCE = 'ryu_ia_app'

class SDNRansomwareDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ... todo lo actual ...
        kwargs['wsgi'].register(RyuIAApi, {API_INSTANCE: self})

    def desbloquear_host(self, ip):
        info = self.blocked_hosts.pop(ip, None)
        if info is None:
            return None
        borradas = 0
        for dpid in info['dpids']:
            dp = self.datapaths.get(dpid)
            if not dp:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=100,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(eth_type=0x0800, ipv4_src=ip),
            )
            dp.send_msg(mod)
            borradas += 1
        # Limpiar TODO el estado del host para que no se vuelva a bloquear de inmediato
        self.host_alert_state.pop(ip, None)
        self.metric_snapshot.pop(ip, None)
        self.host_flow_log.pop(ip, None)
        logger.warning(f'[API] {ip} desbloqueado por el operador ({borradas} regla(s))')
        return borradas


def _json(cuerpo, status=200):
    return Response(status=status, content_type='application/json',
                    charset='utf-8', body=json.dumps(cuerpo).encode('utf-8'))


class RyuIAApi(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[API_INSTANCE]

    def _autorizado(self, req):
        import hmac
        token = req.headers.get('X-Agent-Token', '')
        return bool(AGENT_TOKEN) and hmac.compare_digest(token, AGENT_TOKEN)

    @route('ryu_ia', '/ryu/estado', methods=['GET'])
    def estado(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        return _json({
            'switches': [f'{d:#018x}' for d in self.app.datapaths],
            'hosts_bloqueados': len(self.app.blocked_hosts),
            'umbrales': self.app.umbrales,
            'version': '2.0',
            'pesos': METRIC_WEIGHTS,
        })

    @route('ryu_ia', '/ryu/hosts/bloqueados', methods=['GET'])
    def bloqueados(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        return _json([
            {'ip': ip, 'dpid': f'{info["dpids"][0]:#018x}' if info['dpids'] else None,
             'desde': info['desde']}
            for ip, info in self.app.blocked_hosts.items()
        ])

    @route('ryu_ia', '/ryu/hosts/{ip}/desbloquear', methods=['POST'])
    def desbloquear(self, req, ip, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return _json({'error': 'ip inválida'}, 422)
        borradas = self.app.desbloquear_host(ip)
        if borradas is None:
            return _json({'error': 'host no bloqueado'}, 404)
        return _json({'ok': True, 'ip': ip, 'reglas_borradas': borradas})

    @route('ryu_ia', '/ryu/umbrales', methods=['GET'])
    def leer_umbrales(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        return _json(self.app.umbrales)

    @route('ryu_ia', '/ryu/umbrales', methods=['PUT'])
    def cambiar_umbrales(self, req, **kwargs):
        if not self._autorizado(req): return _json({'error': 'no autorizado'}, 401)
        try:
            cambios = json.loads(req.body or b'{}')
        except ValueError:
            return _json({'error': 'json inválido'}, 422)
        for k, v in cambios.items():
            if k not in self.app.umbrales or not isinstance(v, int) or v <= 0:
                return _json({'error': f'valor inválido para {k}'}, 422)
        self.app.umbrales.update(cambios)
        logger.warning(f'[API] Umbrales actualizados: {cambios}')
        return _json(self.app.umbrales)
```

**Nota:** el desbloqueo borra el DROP de prioridad 100. Si quedaban reglas de rate-limit de la Capa 2 (prioridad 20), expiran solas en 60 a 120 s.

---

## A6. Modo cuarentena — OPCIONAL (para "autonomía acotada")

Solo si hay tiempo. Le permite al agente **desescalar** un bloqueo total a una cuarentena **sin liberar nunca el movimiento lateral**.

| Método | Ruta | Efecto |
|---|---|---|
| POST | `/ryu/hosts/{ip}/cuarentena` | Reemplaza el DROP total por: **DROP de prioridad 110** en TCP 22, 135, 139, 445, 3389 y 5985 desde esa IP, más **DROP de prioridad 100 de todo lo demás, excepto** ARP, DNS (UDP/TCP 53) y DHCP. Respuesta: `{"ok": true, "ip": "...", "modo": "cuarentena"}` |
| POST | `/ryu/hosts/{ip}/bloqueo_total` | Vuelve al DROP total. Respuesta: `{"ok": true, "ip": "...", "modo": "drop_total"}` |
| — | `GET /ryu/hosts/bloqueados` | Agrega el campo `"modo": "drop_total" \| "cuarentena"` |

Ambas son idempotentes, devuelven 404 si el host no está bloqueado y quedan en el log. El host **sigue** en `blocked_hosts` (no vuelve a ser evaluado).

---

## LO QUE NO SE DEBE CAMBIAR (rompe la integración)

1. **Los nombres de los campos de la alerta** en `_send_json_alert`: `timestamp`, `host_origen`, `metricas`, `M1_nuevos_flujos_por_30s`, `M2_destinos_unicos_por_30s`, `M3_smb_anomalo`, `M4_packet_in_por_min`, `M5_flujos_east_west`, `M5_count`, `umbrales_superados`, y los campos nuevos de la v2: `M3_duracion_seg`, `M3_bytes`, `puntaje_total`, `puntaje_maximo`, `pesos_metricas`. Si se renombran (por ejemplo a `KPI-01`), **el agente rechaza la alerta y el bloqueo queda sin registrar ni notificar**. La unificación M1–M5 vs. KPI-01–05 se hace **solo en el documento de tesis**.
2. **El significado de las métricas y del puntaje:** ventanas de 30 s y 60 s, qué cuenta cada una, los pesos (M5=40, M3=35, M1=25, M2=20, M4=15) y los cortes 30/60. Si cambia, avísame primero: las explicaciones y la evaluación dependen de eso.
3. **`AGENT_ENABLED = True`** durante pruebas y demo.
4. **El orden: primero se bloquea y luego se avisa al agente.** Nunca esperar la respuesta del agente para bloquear.
5. **Cualquier campo nuevo se puede AGREGAR a la alerta sin problema** (el agente lo guarda e ignora). Quitar o renombrar, no.

Cualquier cambio a la alerta o a la API: primero se escribe en `docs/contratos.md` del repo del agente y lo aprobamos los dos.

---

## Cómo arrancar

```bash
export AGENT_TOKEN=<token compartido>
ryu-manager ryu_controller.py --ofp-tcp-listen-port 6633 --wsapi-port 8080
```

## Verificación (en este orden)

```bash
# 1. API y token
curl -s localhost:8080/ryu/estado -H "X-Agent-Token: $AGENT_TOKEN"        # 200 con switches
curl -s -o /dev/null -w "%{http_code}\n" localhost:8080/ryu/estado        # 401 sin token

# 2. Umbrales
curl -s -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": 10}'
curl -s -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M9": 1}'   # 422
curl -s -X PUT localhost:8080/ryu/umbrales -H "X-Agent-Token: $AGENT_TOKEN" -d '{"M2": 8}'   # restaurar

# 3. Bloqueo real en Mininet: generar el ataque desde un host y verificar
curl -s localhost:8080/ryu/hosts/bloqueados -H "X-Agent-Token: $AGENT_TOKEN"
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "priority=100"   # repetir en cada switch
#   → en el log de Ryu: "[AGENTE] HTTP 202" y la respuesta con mantener_bloqueo
#   → en el panel del agente: el incidente y el correo

# 4. Desbloqueo
curl -s -X POST localhost:8080/ryu/hosts/<IP>/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | grep "priority=100"   # ya no debe aparecer
#   → en Mininet: <host> ping <otro host> vuelve a responder
curl -s -X POST localhost:8080/ryu/hosts/<IP>/desbloquear -H "X-Agent-Token: $AGENT_TOKEN"  # 404
```

Cuando todo pase, guarda **una alerta real** del log de Ryu (el JSON que imprime `[CAPA 3] Payload JSON`) y envíamela: la uso como prueba fija de compatibilidad en el agente.


---

## Anexo — Formato EXACTO de la alerta (código actual de RYU_IA v2)

Fuente: `docs/referencia/ryu_controller_actual.py` (copia de solo lectura de `sbriceno1379/RYU_IA`, commit 0c434ea del 11-oct-2026). A1 solo cambia la URL y agrega el encabezado del token: el CUERPO no cambia.

```python
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


    def _map_ioc(self, triggered):
        t = set(triggered)
        iocs = []
        if {'M1', 'M2'}.issubset(t): iocs.append('IOC-01')
        if 'M3' in t:                iocs.append('IOC-02')
        if 'M4' in t:                iocs.append('IOC-03')
        if 'M5' in t:                iocs.append('IOC-04')
        if {'M5', 'M1'}.issubset(t): iocs.append('IOC-07')
        score = sum(METRIC_WEIGHTS.get(m, 0) for m in t)
        if score >= SCORE_CRITICAL:  iocs.append('IOC-05')
        return sorted(set(iocs))


    def _get_topology_context(self, src_ip):
        if src_ip.startswith(SUBNET_OPS):
            return f'VLAN OPS (ID={VLAN_OPS}), subred {SUBNET_OPS}0/24'
        if src_ip.startswith(SUBNET_ADM):
            return f'VLAN ADM (ID={VLAN_ADM}), subred {SUBNET_ADM}0/24'
        return 'subred desconocida'
```

Observaciones para el contrato C1:
- `timestamp`: `datetime.utcnow().isoformat() + 'Z'` → con microsegundos, ej. `2026-10-11T05:31:05.123456Z`.
- `dpid_switch`: `f'{datapath.id:#018x}'` → ej. `0x0000000000000001`; puede ser `'unknown'`.
- `contexto_topologico`: TEXTO, ej. `VLAN OPS (ID=10), subred 10.0.10.0/24` o `subred desconocida`.
- M1, M2 y M4 salen de `metric_snapshot` como `float` (ej. `24.0`) o del respaldo como `int`/`float`. `M5_count` igual.
- `M3_smb_anomalo` y `M5_flujos_east_west` son `bool`.
- NUEVOS en v2 dentro de `metricas`: `M3_duracion_seg` y `M3_bytes`, que pueden ser `null` (hoy el código nunca los llena: el snapshot no guarda esas claves).
- NUEVOS en v2 de primer nivel: `puntaje_total` (int), `puntaje_maximo` (135), `pesos_metricas` (dict métrica → peso, solo de las disparadas).
- `umbrales_superados`: lista ordenada de `"M1".."M5"`. `ioc_activados`: lista de `"IOC-0x"`.
- La alerta se envía cuando el **puntaje** llega a 60 o más. Con los pesos actuales puede llegar con **solo 2 métricas** (ej. M5+M1 = 65, M5+M3 = 75) o con 3 (M1+M2+M4 = 60, el ataque de `ataque_completo.py`).
- `solicitud_al_agente` cambió de texto (pide campos como `mensaje_telegram`); el agente lo ignora.
- Valores por defecto (A4/A5): M1=20, M2=8, M3_DURACION_S=5, M3_BYTES=512000, M4=200, M5=5, SCORE_SOSPECHOSO=30, SCORE_CRITICO=60. Pesos: M5=40, M3=35, M1=25, M2=20, M4=15.