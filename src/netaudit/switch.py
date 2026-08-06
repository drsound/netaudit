import re

import paramiko
from netmiko import ConnectHandler


class Switch:
    """Multi-vendor wrapper around netmiko ConnectHandler."""

    def __init__(self, host, user, password=None, device_type='aruba_osswitch', meta=None):
        self.host = host
        self.hostname = None
        #: Inventory metadata for this switch (model, location,
        #: expected_root_mac, ...). Read by the commands that need it.
        self.meta = meta or {}
        self._params = {
            'device_type': device_type,
            'host': host,
            'username': user,
            'password': password if password else '',
        }
        self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def connect(self):
        # Try keys from the SSH agent one by one. Necessary because some
        # SSH servers (like Mocana, used by Aruba/HP) close the connection after
        # the first pubkey failure instead of allowing further attempts.
        agent_keys = []
        try:
            agent_keys = list(paramiko.Agent().get_keys())
        except Exception:
            pass

        # Every attempt is recorded: reporting only the last one would hide the
        # error that actually matters (e.g. a wrong password behind an unrelated
        # pubkey failure).
        failures = []
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
                failures.append(f"agent key {pkey.get_name()}: {e}")

        # Fallback: password authentication (no agent keys available
        # or no key accepted by the switch)
        if self._params['password']:
            try:
                self._conn = ConnectHandler(**self._params)
                self.hostname = self._conn.base_prompt
                return
            except Exception as e:
                last_exc = e
                failures.append(f"password: {e}")
        else:
            failures.append('password: no password configured')

        detail = '\n  '.join(f.replace('\n', ' ').strip() for f in failures)
        raise ConnectionError(
            f"all authentication methods failed:\n  {detail}"
        ) from last_exc

    def close(self):
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass

    def run(self, cmd, timeout=30):
        """Executes a command in exec mode and returns the clean output."""
        return self._conn.send_command(cmd, read_timeout=timeout)

    def configure(self, cmds):
        """Executes a list of commands in config mode. Handles [y/n] prompts."""
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
