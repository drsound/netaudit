from .diagnostics import get_vlan, get_vlans, get_running_config, get_port_names


def _confirm(yes=False):
    if yes:
        return True
    resp = input("Confirm? [y/N]: ").strip().lower()
    return resp in ('y', 'yes')


def _preview(cmds):
    print("Commands that will be executed:")
    for cmd in cmds:
        print(f"  {cmd}")
    print()


def rename_vlan(sw, vlan_id, name, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'name "{name}"',
        'exit',
    ]
    print(f"\n[RENAME VLAN {vlan_id} → \"{name}\"]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def create_vlan(sw, vlan_id, name, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'name "{name}"',
        'exit',
    ]
    print(f"\n[CREATE VLAN {vlan_id} - {name}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def delete_vlan(sw, vlan_id, yes=False):
    # Safety check: look for active ports in this VLAN before deleting
    vlan_info = get_vlan(sw, vlan_id)
    if 'Invalid' in vlan_info or 'does not exist' in vlan_info.lower():
        print(f"VLAN {vlan_id} does not exist.")
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
        print(f"WARNING: VLAN {vlan_id} has active ports:")
        if untagged:
            print(f"  Untagged: {', '.join(untagged)}")
        if tagged:
            print(f"  Tagged: {', '.join(tagged)}")
        print()

    cmds = [f'no vlan {vlan_id}']
    print(f"\n[DELETE VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify (VLAN {vlan_id} should not appear):")
    print(get_vlans(sw))


def set_port_access(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'untagged {port}',
        'exit',
    ]
    print(f"\n[PORT {port} → ACCESS VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def add_port_tagged(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'tagged {port}',
        'exit',
    ]
    print(f"\n[PORT {port} → TAGGED VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def remove_port_tagged(sw, port, vlan_id, yes=False):
    cmds = [
        f'vlan {vlan_id}',
        f'no tagged {port}',
        'exit',
    ]
    print(f"\n[REMOVE PORT {port} FROM TAGGED VLAN {vlan_id}]")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify VLAN {vlan_id}:")
    print(get_vlan(sw, vlan_id))


def set_port_name(sw, port, name, yes=False):
    if name:
        cmds = [f'interface {port}', f'name "{name}"', 'exit']
        label = f"[SET PORT {port} NAME → \"{name}\"]"
    else:
        cmds = [f'interface {port}', 'no name', 'exit']
        label = f"[REMOVE PORT {port} NAME]"

    print(f"\n{label}")
    _preview(cmds)

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.configure(cmds)
    if output:
        print(output)

    print(f"\nVerify port {port}:")
    print(get_port_names(sw, port=port))


def save_config(sw, yes=False):
    print("\n[SAVE CONFIGURATION — write memory]")
    print("This saves the running-config to startup-config.\n")

    if not _confirm(yes):
        print("Operation cancelled.")
        return

    output = sw.run('write memory', timeout=60)
    print(output)
