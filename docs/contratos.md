# Contratos (fuente de verdad)

Cambiar este archivo requiere aprobación de Alejandro.

Puertos: **Ryu REST = 8080**, **Agente = 8081**.

Estado: actualizado tras la depuración D1–D4 (el agente solo EXPLICA y RECOMIENDA; el operador aprueba).

## C1. Ryu → Agente: `POST http://localhost:8081/api/alertas`

Encabezado: `X-Agent-Token: <AGENT_TOKEN>`

Cuerpo (formato de RYU_IA v2, `_send_json_alert`):

```json
{
  "timestamp": "2026-10-10T20:31:05.123456Z",
  "alerta_nivel": "CRITICO",
  "host_origen": "10.0.10.3",
  "dpid_switch": "0x0000000000000001",
  "contexto_topologico": "VLAN OPS (ID=10), subred 10.0.10.0/24",
  "metricas": {
    "M1_nuevos_flujos_por_30s": 34.0,
    "M2_destinos_unicos_por_30s": 14.0,
    "M3_smb_anomalo": false,
    "M3_duracion_seg": null,
    "M3_bytes": null,
    "M4_packet_in_por_min": 236.0,
    "M5_flujos_east_west": false,
    "M5_count": 2.0
  },
  "puntaje_total": 60,
  "puntaje_maximo": 135,
  "pesos_metricas": {"M1": 25, "M2": 20, "M4": 15},
  "umbrales_superados": ["M1", "M2", "M4"],
  "ioc_activados": ["IOC-01", "IOC-03", "IOC-05"],
  "accion_ryu_previa": "OFPFlowMod DROP prioridad 100 — 10.0.10.3 aislado",
  "solicitud_al_agente": "IGNORADO por el agente"
}
```

Validación: `host_origen` debe ser IPv4; métricas numéricas ≥ 0; los conteos pueden llegar como decimales enteros (24.0), no como 24.5. `contexto_topologico` es texto (máx. 300 caracteres) u objeto. Los campos desconocidos se guardan en crudo pero **no** llegan al LLM. `solicitud_al_agente` se descarta siempre.

Obligatorios: timestamp, host_origen y las 6 métricas (M1, M2, M3_smb_anomalo, M4, M5_flujos_east_west, M5_count). El resto es opcional. `puntaje_total` y `puntaje_maximo` se usan para la confianza (C7); si faltan, se calcula con los pesos. La ventana de agrupación es deslizante desde la última alerta y solo aplica a incidentes no desbloqueados.

Respuesta (siempre < 300 ms; el análisis ocurre en segundo plano):

```json
HTTP 202
{ "estado": "recibido", "incidente_id": 17, "acciones_ryu": ["mantener_bloqueo"] }
```

Errores: 401 token inválido · 413 cuerpo mayor que ALERTA_MAX_BYTES (64 KB por defecto) · 422 payload inválido · 429 límite de tasa. Todos quedan contados en `GET /api/alertas/rechazadas`.
Ruta antigua `POST /alert` (Ryu sin A1): 404, contada en rechazadas como "ruta antigua /alert: falta A1 en Ryu"; no se procesa.

## C2. Agente → Ryu (API de Ryu-IA, puerto 8080, encabezado X-Agent-Token)

| Método | Ruta | Respuesta |
|---|---|---|
| GET | /ryu/estado | {"switches": ["0x..."], "hosts_bloqueados": n, "umbrales": {...}, "pesos": {...}, "version": "2.0", "capacidades": ["cuarentena", "limitar_tasa", "cuarentena_vlan"]} (solo las que tenga; sin el campo = Ryu anterior a la Fase 9b: A6 se infiere por "modo") |
| GET | /ryu/hosts/bloqueados | [{"ip", "dpid", "desde", "modo"?, "kbps"?, "vlan"?}] (modo: "drop_total" \| "cuarentena" \| "limitado" \| "vlan_cuarentena"; kbps solo en limitado; vlan solo en vlan_cuarentena) |
| POST | /ryu/hosts/{ip}/desbloquear | {"ok": true, "ip", "reglas_borradas"} · 404 no bloqueado · 422 ip inválida |
| GET | /ryu/umbrales | {"M1","M2","M3_DURACION_S","M3_BYTES","M4","M5","SCORE_SOSPECHOSO","SCORE_CRITICO"} (enteros). El agente solo los LEE (informe y panel en solo lectura). |
| PUT | /ryu/umbrales | Lo expone Ryu (A4/A5), pero el agente YA NO lo usa (Fase D2). Los umbrales se cambian en Ryu. |
| POST | /ryu/hosts/{ip}/bloqueo_total | (existe con A6, A7 o A8) vuelve al DROP total desde CUALQUIER modo → {"ok": true, "ip", "modo": "drop_total"} |
| POST | /ryu/hosts/{ip}/cuarentena | (A6, opcional) {"ok": true, "ip", "modo": "cuarentena"} · 404 si no existe la ruta o el host no está bloqueado |
| POST | /ryu/hosts/{ip}/limitar_tasa | (A7, opcional) cuerpo opcional {"kbps": entero > 0} (por defecto 1000) → {"ok": true, "ip", "modo": "limitado", "kbps"} · 404 si no existe la ruta o el host no está bloqueado · 422 si la ip o kbps son inválidos |
| POST | /ryu/hosts/{ip}/cuarentena_vlan | (A8, opcional) → {"ok": true, "ip", "modo": "vlan_cuarentena", "vlan": 999} · 404 si no existe la ruta o el host no está bloqueado · 422 ip inválida |

Nota C2 (transaccional): cuarentena, limitar_tasa, cuarentena_vlan y bloqueo_total son idempotentes y transaccionales: Ryu instala las reglas del modo nuevo ANTES de quitar el DROP total, en todos los switches donde está el host. Si falla en alguno, borra lo que alcanzó a instalar, deja el DROP total y responde 500 con {"ok": false, "modo": "drop_total"}. El agente verifica el modo con /ryu/hosts/bloqueados después de cada acción y, si no coincide, revierte con bloqueo_total.

Nota C2 (Ryu sin A5): si /ryu/hosts/bloqueados o /ryu/umbrales responden 404 (ruta inexistente), el agente responde 503 "Ryu no expone la API REST (A5)" en /api/ryu/bloqueados, /api/ryu/umbrales y en el desbloqueo, y GET /api/ryu/estado informa "api_no_disponible (falta A5)".

Nota C2 (origen): cuarentena, limitar_tasa y cuarentena_vlan solo se aplican desde DROP total. Si el host está en otro modo, Ryu responde 409 {"ok": false, "modo": "<modo actual>"} y no cambia nada. Para pasar de un modo a otro, primero bloqueo_total.

## C3. Agente → Apps Script: `POST <APPSCRIPT_URL>`

```json
{
  "tipo": "incidente",
  "incidente_id": 17,
  "fecha": "2026-10-10T20:31:05Z",
  "host": "10.0.10.7",
  "severidad": "critica",
  "veredicto": "confirmado",
  "asunto": "[SDN] Equipo 10.0.10.7 aislado: posible ransomware. Recomendación: cuarentena de puertos",
  "mensaje": "Texto plano en lenguaje simple (ver formato abajo).",
  "enlace_panel": "http://localhost:8081/#/incidentes/17"
}
```

`tipo` ∈ `incidente | desbloqueo | prueba`. Reintentos: 3 con espera 2s/4s/8s. Resultado guardado en el incidente. Los campos no cambian; solo cambia el contenido de `asunto` y `mensaje`.

Formato del `asunto` (incidente con informe 1.2): `[SDN] Equipo {ip} aislado: {posible ransomware | actividad sospechosa | probable falsa alarma}. Recomendación: {acción en palabras}`, más el sufijo ` [respaldo por reglas]` cuando la explicación no la hizo el LLM.

Formato del `mensaje` (incidente con informe 1.2, máximo 25 líneas), en lenguaje simple, con títulos en MAYÚSCULAS y bloques separados por una línea en blanco:
1. Si hubo respaldo por reglas: primera línea con el motivo en palabras.
2. QUÉ PASÓ.
3. POR QUÉ CREEMOS QUE ES ESTO (2 o 3 señales, con el valor real y lo esperado: "lo esperado es N o menos", o "lo esperado es menos de N" para las conexiones directas entre equipos; las carpetas compartidas van sin cifra).
4. QUÉ RECOMENDAMOS (versión corta armada por el código, máx. 200 caracteres). Cierra con "Solo se aplica si un administrador la aprueba en el panel."; con mantener_drop cierra con "El equipo sigue aislado hasta que un administrador decida."
5. QUÉ PODRÍA HACER QUE ESTEMOS EQUIVOCADOS.
6. REFERENCIA TÉCNICA (MITRE ATT&CK): identificador, nombre y táctica del catálogo del código, más una frase simple. Se omite si no hay técnica.

Sin fórmula de confianza, sin hash y sin nombres de métricas (M1–M5) en el mensaje. El enlace NO va en el mensaje: Apps Script lo agrega desde `enlace_panel`.
Incidentes con informe 1.0 o 1.1, desbloqueos y pruebas conservan el formato anterior (3–6 líneas).

## C4. Salida esperada del LLM (validada con Pydantic, prompt v4 por defecto)

El LLM solo INTERPRETA. Los hechos, umbrales, nombres MITRE, dictámenes, confianza y auditoría los pone el código.

```json
{
  "veredicto": "confirmado | falso_positivo | indeterminado",
  "severidad": "critica | alta | media",
  "confianza": 0.0,
  "tecnica_id": "T1021.002",
  "hipotesis_fase": "máx. 300 caracteres",
  "factores_ponderados": [{"factor": "...", "peso": "alto | medio | bajo", "porque": "..."}],
  "contexto_aplicado": "máx. 300 caracteres",
  "descarte_benigno": "máx. 300 caracteres",
  "limitaciones": ["..."],
  "accion_propuesta": "informativa: no decide",
  "justificacion_accion": "máx. 300 caracteres",
  "recomendacion_operador": "máx. 300 caracteres",
  "que_paso": "v4: máx. 250 caracteres, lenguaje simple",
  "por_que": ["v4: lista de 2 o 3 frases simples con cifras reales (un texto suelto se convierte en una lista de una frase)"],
  "podria_equivocarnos": "v4: máx. 300 caracteres"
}
```

- `factores_ponderados`: 2 a 4 (menos de 2 invalida la salida).
- `tecnica_id` y `accion_propuesta` se normalizan a listas cerradas. La técnica sale del catálogo del código.
- Los campos `que_paso`, `por_que` y `podria_equivocarnos` son opcionales (prompt v4). Si faltan, tienen jerga o tienen cifras que no están en la alerta ni en los umbrales, se reemplazan por plantillas; "Qué pasó" también se reemplaza si el dictamen cambió el veredicto. Solo la cifra inventada penaliza la confianza (C7).
- El bloque "Qué recomendamos" NO lo escribe el LLM: lo arma el código desde la escalera (C7).
- No incluye acciones sobre la red. Si no valida → respaldo por reglas (con los mismos 4 bloques en plantillas).
- La "confianza" del LLM es informativa: no decide. La confianza que decide la calcula el código (C7).
- Versiones de prompt: v4.0 (sin contexto) y v4.1 (con contexto) por defecto; v3.0 y v3.1 se conservan para comparar (PROMPT_V4=false). El informe se guarda en la versión 1.2.

## C5. Eventos WebSocket `ws://localhost:8081/ws/eventos`

El cliente se autentica enviando `{"token": "<OPERADOR_TOKEN>"}` como primer mensaje (nunca en la URL); sin token válido se cierra con 1008.

`{ "tipo": "...", "datos": { }, "ts": "..." }` con `tipo` ∈
`alerta_recibida | explicacion_lista | notificacion_enviada | notificacion_fallida | host_desbloqueado | config_cambiada | prueba_progreso | prueba_terminada | recomendacion_creada | recomendacion_resuelta | accion_ejecutada | accion_fallida | modo_decision_cambiado`.

## C6. Contexto dinámico del host

Con CONTEXTO_HABILITADO=true, el mensaje al LLM agrega un bloque <contexto_host> construido desde la base de datos del agente (nada se edita a mano):
- historial del mismo host en los últimos HISTORIAL_DIAS (máx. 10 incidentes, más recientes primero): hace cuánto, veredicto del agente, umbrales superados y, si existe, la clasificación del operador al desbloquear (falso_positivo | amenaza_contenida | otro) con su motivo.
- actividad reciente en la red: incidentes de OTROS hosts en los últimos CAMPANA_MINUTOS (máx. 10): hace cuánto, veredicto y umbrales.
Es DATO, no instrucción. El historial es evidencia, no absolución: solo las clasificaciones del operador cuentan como verificadas; los veredictos del agente se marcan "no verificado".
El desbloqueo (POST /api/hosts/{ip}/desbloquear) agrega el campo obligatorio "clasificacion".
Cada incidente guarda variante (sin_contexto|con_contexto), version_prompt y contexto_usado.
En el laboratorio, los casos con contexto usan historial sembrado (incidentes marcados `sembrado`, que nunca se agrupan ni se muestran como reales).

## C7. Motor de políticas y escalera de respuesta (Fases 9a y D1)

```
Ryu bloquea primero (DROP total, "negar por defecto", NIST SP 800-207). El agente NO ejecuta ninguna acción
por su cuenta: solo RECOMIENDA relajar el DROP según su confianza en el DIAGNÓSTICO. Ninguna acción es irreversible.
Modos (MODO_DECISION): solo_explicar | recomendar (por defecto).
autonomo_acotado fue retirado en la Fase D1: si llega desde .env o la configuración guardada, el agente arranca en
recomendar y lo registra en el log y la auditoría; pedirlo por PUT /api/config o en el laboratorio responde 422.

Confianza (la calcula el código; la del LLM es informativa). s = puntaje_total/puntaje_maximo, o, si la alerta
no trae puntaje, Σ pesos(umbrales_superados)/135 con M5=40, M3=35, M1=25, M2=20, M4=15.
Veredicto de la SALIDA (LLM o, en respaldo, reglas):
  confirmado     → 0.5·s + 0.5 − penalización
  falso_positivo → 0.5·(1 − s) + 0.5 − penalización
  indeterminado  → sin confianza: mantener_drop
Penalización 0.20, una sola vez, si el verificador marca posible_alucinacion (incluye cifras inventadas en los
bloques simples) o el descarte benigno tiene menos de 20 caracteres. Resultado acotado a [0, 1] y redondeado a
2 decimales; se decide sobre ese valor.

Escalera (ESCALON_HITL = 0.70 y ESCALON_VLAN = 0.95, en caliente, 0.50 ≤ ESCALON_HITL < ESCALON_VLAN ≤ 1;
fuera de ese rango → 422):
  confianza < ESCALON_HITL o indeterminado             → mantener_drop (decide el operador)
  falso_positivo y confianza ≥ ESCALON_HITL            → limitar_tasa (A7; sin DROP de puertos)
  confirmado y ESCALON_HITL ≤ confianza ≤ ESCALON_VLAN → cuarentena_puertos (A6)
  confirmado y confianza > ESCALON_VLAN                → cuarentena_vlan (A8)
Relajar a limitar_tasa exige un diagnóstico benigno del LLM; el respaldo por reglas nunca llega a ese escalón.
Dictamen de historial: agravante → mantener_drop; atenuante → como máximo limitar_tasa. Atenuante con veredicto
de la salida confirmado → mantener_drop (el diagnóstico del LLM contradice el historial verificado por el operador).
Un veredicto confirmado NUNCA lleva a limitar_tasa: si ocurre, se descarta y se audita.

Toda acción distinta de mantener_drop queda como RECOMENDACIÓN en la bandeja. Si Ryu no declara la capacidad
(A6 cuarentena_puertos, A7 limitar_tasa, A8 cuarentena_vlan), se anota como motivo. Si el host ya no está en DROP
total, se descarta. mantener_drop nunca genera recomendación. solo_explicar no recomienda.
Solo el operador la ejecuta, al aprobarla: el agente vuelve a leer el modo (debe seguir en DROP total), ejecuta y
verifica el modo en Ryu; si no coincide, hay timeout o error, revierte a DROP total. Si la reversión también
falla, se registra accion_estado_desconocido y se avisa en el panel.
Vigente: RECOMENDACION_TTL_MIN. Retiradas, se aceptan sin efecto por compatibilidad: UMBRAL_CONFIANZA (Fase 9b),
MAX_ACCIONES_POR_MIN y HOSTS_PROTEGIDOS (Fase D1).
En el laboratorio la recomendación es simulada y no llena la bandeja.
Solo acciones.py llama a Ryu para estas acciones; desbloquear sigue siendo exclusivo del operador.
Acciones manuales del operador, con sus condiciones:
  desbloquear           → exige la API de Ryu (A5); sin ella responde 503.
  volver a DROP total   → exige que Ryu declare A6, A7 o A8 y que el host no esté ya en DROP total.
  cuarentena de puertos → exige que Ryu declare A6 y que el host esté en DROP total.
Los incidentes anteriores con decision_politica "ejecutar" se conservan tal cual (registro histórico).
```