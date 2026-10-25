# CLAUDE.md - Reglas del proyecto RYU_IA (controlador SDN)

Lee este archivo completo antes de cada tarea. Si una instruccion choca con estas reglas, pregunta antes de actuar.

## 1. Que es este proyecto

Tesis de grado, Universidad Catolica de Colombia (autores: Alejandro Salas Jurado y Sebastian Briceno Restrepo). Respuesta a movimiento lateral de ransomware en una red SDN.

Este repo es el controlador Ryu (OpenFlow 1.3, puerto 6633) con la topologia de Mininet (3 switches, VLAN OPS y ADM) y los scripts de ataque. Detecta con 5 metricas y un puntaje ponderado: M5=40, M3=35, M1=25, M2=20, M4=15 (maximo 135); sospechoso desde 30, critico desde 60.

El otro repo, sdn-agent-v2 (en ~/Desktop/sdn-agent-v2), es el agente LLM. Ya esta terminado y probado contra un mock que imita este controlador. Este repo debe quedar compatible con ese agente.

Flujo completo:
1. Ryu detecta y BLOQUEA primero (DROP total en todos los switches).
2. Ryu envia la alerta JSON al agente: POST http://localhost:8081/api/alertas con el encabezado X-Agent-Token.
3. El agente responde 202 al instante: {"estado":"recibido","incidente_id":N,"acciones_ryu":["mantener_bloqueo"]}.
4. El agente explica, recomienda una accion y notifica por correo y en su panel.
5. Solo si un operador humano aprueba en el panel, el agente llama a la API REST de Ryu (puerto 8080) para desbloquear o aplicar una accion de la escalera.

## 2. Reglas de dominio que nunca se rompen

- Primero se bloquea y luego se avisa al agente. Nunca se espera la respuesta del agente para bloquear.
- Ryu nunca desbloquea por su cuenta ni por lo que responda el agente. Solo desbloquea por la API, cuando el operador lo aprueba.
- No se cambia la logica de deteccion M1 a M5, el puntaje, los pesos ni los cortes 30 y 60.
- No se quitan ni se renombran campos de la alerta (lista en docs/ajustes.md, seccion "LO QUE NO SE DEBE CAMBIAR"). Agregar campos si se puede.
- Toda la API REST exige X-Agent-Token (401 si falta o no coincide).
- Ningun secreto en el codigo: el token se lee de la variable de entorno AGENT_TOKEN.

## 3. Documentos de referencia (solo lectura, no los edites)

- docs/ajustes.md: los cambios A0 a A6 que necesita este controlador, con codigo de ejemplo y verificacion.
- docs/contratos.md: el contrato con el agente. C1 es el formato de la alerta y C2 la API de Ryu, incluidas A7 (limitar_tasa) y A8 (cuarentena_vlan).
Si algo de estos documentos no coincide con el codigo, detente y avisa. No lo resuelvas por tu cuenta.

## 4. Plan por fases

| Fase | Entrega | Estado |
|---|---|---|
| R0 | Entorno: Ryu, Mininet y Open vSwitch instalados; prueba de humo con pingall | en curso |
| R1 | A0 a A5 en ryu_controller.py (valores de metricas, envio al agente, sin desbloqueo automatico, bloqueo en todos los switches, umbrales editables, API REST) | pendiente |
| R2 | Integracion real: Ryu mas Mininet mas el agente, con los scripts de ataque | pendiente |
| R3 | A6, A7 y A8 en Ryu (cuarentena por puertos, limitar tasa, cuarentena VLAN 999 con honeypot) | pendiente |
| R4 | Evaluacion final de la tesis | pendiente |

## 5. Como trabajar

1. Haz solo lo que pide la fase actual. Si ves algo que estaria bien agregar, escribelo en docs/ideas.md con una linea y sigue.
2. En cada fase: primero valida (lee el codigo y revisa), luego propone en pocas lineas que archivos tocaras y que no, y espera mi aprobacion. Solo entonces implementa.
3. No asumas nada. Si un dato no se puede comprobar, dilo.
4. Cambios minimos: no reescribas archivos completos para un cambio pequeno, no renombres ni muevas archivos.
5. No agregues dependencias sin que yo lo pida por escrito.
6. No uses sudo. Si algo lo necesita, dame el comando exacto y yo lo ejecuto.
7. No modifiques nada de ~/Desktop/sdn-agent-v2. Puedes leerlo si hace falta.
8. Al terminar una fase: muestra lo que se probo y su resultado y un resumen de maximo 8 lineas (que cambio, que quedo pendiente). Una fase es un commit.
9. Nunca hagas git add ni git commit sin que yo lo apruebe en ese momento. Al terminar una fase, muestrame el diff y propon el mensaje del commit; yo decido.