import pexpect
import re


def strip_ansi(text):
    # Covers: CSI sequences with optional ? or digit/semicolon parameters
    ansi_escape = re.compile(r'\x1b\[[\d;?]*[a-zA-Z]|\r')
    return ansi_escape.sub('', text)


class ArubaSwitch:
    def __init__(self, host, user, password, **kwargs):
        self.host = host
        self.user = user
        self.password = password
        self.child = None
        self.hostname = None
        self._prompt_priv = None   # regex for privileged exec: hostname#
        self._prompt_any = None    # regex for any mode: hostname(context)#

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def _build_prompts(self, hostname):
        self.hostname = hostname
        escaped = re.escape(hostname)
        # Aruba prompts always end with '# ' or '> ' (space after the symbol)
        self._prompt_priv = rf'{escaped}# '
        self._prompt_any = rf'{escaped}(?:\([^)]+\))?[#>] '

    def connect(self):
        self.child = pexpect.spawn(
            f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {self.user}@{self.host}',
            encoding='utf-8',
            timeout=60,
        )

        # Handle login loop: password prompt, "press any key" banner, SSH host key, or direct prompt
        prompt_text = None
        while prompt_text is None:
            i = self.child.expect([
                r'[Pp]assword:',
                r'[Pp]ress any key',
                r'continue connecting',
                r'[#>] ',
                pexpect.TIMEOUT,
                pexpect.EOF,
            ])
            if i == 0:
                self.child.sendline(self.password)
            elif i == 1:
                self.child.send(' ')
            elif i == 2:
                self.child.sendline('yes')
                self.child.expect(r'[Pp]assword:')
                self.child.sendline(self.password)
            elif i == 3:
                # child.after = '# ' or '> '; hostname is the last word of child.before
                before = strip_ansi(self.child.before)
                m_host = re.search(r'([\w][\w\-]*)$', before.rstrip())
                if not m_host:
                    raise ConnectionError(f"Cannot parse hostname from buffer: {before!r}")
                prompt_text = m_host.group(1) + self.child.after.strip()  # e.g. 'hostname#'
            elif i == 4:
                raise ConnectionError(f"Timeout connecting to {self.host}")
            elif i == 5:
                raise ConnectionError(f"Connection refused or EOF from {self.host}")

        # Extract hostname from 'hostname# ' or 'hostname> '
        m = re.match(r'([\w][\w\-]*)[#>]', prompt_text)
        if not m:
            raise ConnectionError(f"Cannot parse hostname from prompt: {prompt_text!r}")
        self._build_prompts(m.group(1))

        # Enter privileged mode if we landed in user exec
        if '>' in prompt_text:
            self.child.sendline('enable')
            i = self.child.expect([r'[Pp]assword:', self._prompt_priv])
            if i == 0:
                self.child.sendline(self.password)
                self.child.expect(self._prompt_priv)

        # Disable paging so output is never truncated
        self.child.sendline('no page')
        self.child.expect(self._prompt_priv)

    def close(self):
        if self.child:
            try:
                self.child.sendline('exit')
                self.child.expect([pexpect.EOF, r'[#>] ', r'y/n'], timeout=5)
                if self.child.after and 'y/n' in str(self.child.after):
                    self.child.sendline('y')
                    self.child.expect(pexpect.EOF, timeout=5)
            except Exception:
                pass
            try:
                self.child.close()
            except Exception:
                pass

    def run(self, cmd, timeout=30):
        """Execute a command in privileged exec mode and return cleaned output."""
        self.child.sendline(cmd)
        self.child.expect(self._prompt_any, timeout=timeout)
        output = strip_ansi(self.child.before)
        # Remove the command echo from the beginning of the output
        idx = output.find(cmd)
        if idx >= 0:
            output = output[idx + len(cmd):]
        return output.strip()

    def configure(self, cmds):
        """Execute a list of commands in config mode. Returns aggregated output."""
        output = []
        self.child.sendline('configure terminal')
        self.child.expect(self._prompt_any, timeout=15)

        for cmd in cmds:
            self.child.sendline(cmd)
            # Some commands (es. 'no vlan') chiedono una conferma aggiuntiva
            i = self.child.expect([self._prompt_any, r'\[y/n\]'], timeout=15)
            if i == 1:
                self.child.sendline('y')
                self.child.expect(self._prompt_any, timeout=15)
            out = strip_ansi(self.child.before).strip()
            if out:
                output.append(out)

        # 'end' returns to privileged exec from any config level
        self.child.sendline('end')
        self.child.expect(self._prompt_priv, timeout=15)
        return '\n'.join(output)
