# Ideas (fuera de la fase actual)

- El rate-limit de la Capa 2 (`_apply_rate_limit`) se instala en un solo switch, no en todos.
- `self.datapaths` nunca quita los switches que se desconectan (no hay manejador de EventOFPStateChange).
- Un switch que se conecte después de un bloqueo no recibe el DROP de los hosts ya bloqueados.
- `arranque_ryu.py` busca `ryu-manager` en el PATH y no en `.venv/bin/`.
- Detectar errores asincronos del switch (Barrier + OFPErrorMsg) en las acciones de cuarentena; hoy solo se detecta switch desconectado.
- El aislamiento entre VLAN depende de Ryu (salidas explicitas y FLOOD ignoran los tags de OVS; el ARP cruza VLAN; la regla es OPS contra no OPS por IP)
- M3 no puede dispararse: solo se evalúa sobre reglas con ipv4_src/ipv4_dst/tcp_dst=445, que hoy son las de monitoreo M5, permanentes (duration > 5 s). Lo comprueba el escenario A3 de evaluacion/.
- El conjunto east_west de M5 no tiene ventana de tiempo: un host benigno acumula pares (destino, puerto) sin límite hasta que se desbloquea o se reinicia Ryu.
