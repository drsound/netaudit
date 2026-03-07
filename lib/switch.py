import re
import paramiko
from netmiko import ConnectHandler


class Switch:
    """Wrapper multi-vendor attorno a netmiko ConnectHandler."""

    def __init__(self, host, user, password, device_type='aruba_osswitch', **kwargs):
        self.host = host
        self.hostname = None
        self._params = {
            'device_type': device_type,
            'host': host,
            'username': user,
            'password': password,
        }
        self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def connect(self):
        # Prova le chiavi dall'SSH agent una alla volta. Necessario perché alcuni
        # server SSH (Mocana, usato da Aruba/HP) chiudono la connessione dopo il
        # primo fallimento pubkey invece di permettere ulteriori tentativi.
        agent_keys = []
        try:
            agent_keys = list(paramiko.Agent().get_keys())
        except Exception:
            pass

        last_exc = None
        for pkey in agent_keys:
            try:
                self._conn = ConnectHandler(
                    **self._params, pkey=pkey, allow_agent=False, use_keys=False
                )
                self.hostname = self._conn.base_prompt
                return
            except Exception as e:
                last_exc = e

        # Fallback: autenticazione con password (nessuna chiave agent disponibile
        # o nessuna chiave accettata dallo switch)
        try:
            self._conn = ConnectHandler(**self._params)
            self.hostname = self._conn.base_prompt
        except Exception as e:
            raise ConnectionError(str(last_exc or e)) from (last_exc or e)

    def close(self):
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass

    def run(self, cmd, timeout=30):
        """Esegue un comando in modalità exec e restituisce l'output pulito."""
        return self._conn.send_command(cmd, read_timeout=timeout)

    def configure(self, cmds):
        """Esegue una lista di comandi in config mode. Gestisce conferme [y/n]."""
        self._conn.config_mode()
        output = []
        for cmd in cmds:
            out = self._conn.send_command_timing(cmd, read_timeout=15)
            if re.search(r'\[y/n\]', out, re.IGNORECASE):
                out += self._conn.send_command_timing('y', read_timeout=5)
            if out.strip():
                output.append(out.strip())
        self._conn.exit_config_mode()
        return '\n'.join(output)
