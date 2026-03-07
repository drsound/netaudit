from .diagnostics import get_vlan, get_vlans, get_running_config, get_port_names


def _confirm(yes=False):
    if yes:
        return True
    resp = input("Confermare? [s/N]: ").strip().lower()
    return resp in ('s', 'si', 'y', 'yes')


def _preview(cmds):
    print("Comandi che verranno eseguiti:")
    for cmd in cmds:
        print(f"  {cmd}")
    print()


def rename_vlan(sw, vlan_id, name, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'name "{name}"',
        'exit',
    ]
    print(f"\n[RINOMINA VLAN {vlan_id} → \"{name}\"]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def create_vlan(sw, vlan_id, name, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'name "{name}"',
        'exit',
    ]
    print(f"\n[CREA VLAN {vlan_id} - {name}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def delete_vlan(sw, vlan_id, yes=False):
    # Safety check: look for active ports in this VLAN before deleting
    vlan_info = get_vlan(sw, vlan_id)
    if 'Invalid' in vlan_info or 'does not exist' in vlan_info.lower():
        print(f"VLAN {vlan_id} non esiste.")
        return

    # Check for tagged/untagged ports
    tagged = []
    untagged = []
    for line in vlan_info.splitlines():
        if 'Tagged' in line or 'Untagged' in line:
            # Lines like: "   Tagged Ports  : A1, A2"
            import re
            m = re.match(r'\s*(Tagged|Untagged)\s+Ports?\s*:\s*(.+)', line)
            if m and m.group(2).strip():
                ports = m.group(2).strip()
                if m.group(1) == 'Tagged':
                    tagged.append(ports)
                else:
                    untagged.append(ports)

    if tagged or untagged:
        print(f"ATTENZIONE: La VLAN {vlan_id} ha porte attive:")
        if untagged:
            print(f"  Untagged: {', '.join(untagged)}")
        if tagged:
            print(f"  Tagged: {', '.join(tagged)}")
        print()

    cmds = [f'no vlan {vlan_id}']
    print(f"\n[ELIMINA VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica (VLAN {vlan_id} non deve apparire):")
    print(get_vlans(sw))


def set_port_access(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'untagged {port}',
        'exit',
    ]
    print(f"\n[PORTA {port} → ACCESS VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def add_port_tagged(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'tagged {port}',
        'exit',
    ]
    print(f"\n[PORTA {port} → TAGGED VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def remove_port_tagged(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'no tagged {port}',
        'exit',
    ]
    print(f"\n[RIMUOVI PORTA {port} DA TAGGED VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def set_port_name(sw, port, name, yes=False):
    if name:
        cmds = [f'interface {port}', f'name "{name}"', 'exit']
        label = f"[IMPOSTA NOME PORTA {port} → \"{name}\"]"
    else:
        cmds = [f'interface {port}', 'no name', 'exit']
        label = f"[RIMUOVI NOME PORTA {port}]"

    print(f"\n{label}")
    _preview(cmds)

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerifica porta {port}:")
    print(get_port_names(sw, port=port))


def save_config(sw, yes=False):
    print("\n[SALVA CONFIGURAZIONE — write memory]")
    print("Questo salva la running-config in startup-config.\n")

    if not _confirm(yes):
        print("Operazione annullata.")
        return

    output = sw.run('write memory', timeout=60)
    print(output)
