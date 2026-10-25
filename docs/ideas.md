# Ideas (fuera de la fase actual)

- El rate-limit de la Capa 2 (`_apply_rate_limit`) se instala en un solo switch, no en todos.
- `self.datapaths` nunca quita los switches que se desconectan (no hay manejador de EventOFPStateChange).
- Un switch que se conecte después de un bloqueo no recibe el DROP de los hosts ya bloqueados.
- `arranque_ryu.py` busca `ryu-manager` en el PATH y no en `.venv/bin/`.
- Detectar errores asincronos del switch (Barrier + OFPErrorMsg) en las acciones de cuarentena; hoy solo se detecta switch desconectado.
