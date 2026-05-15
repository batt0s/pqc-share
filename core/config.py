"""PQC-Share Configuration Parser"""

from pathlib import Path


def load_config(config_path="~/.pqc_share/config") -> dict:
    """
    Read the config file and turn into a dict
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        return {}

    aliases = {}
    current_host = None

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            key = parts[0].lower()

            if key == "host" and len(parts) > 1:
                current_host = parts[1]
                aliases[current_host] = {}
            elif current_host:
                val = " ".join(parts[1:])
                aliases[current_host][key] = val

    return aliases


def resolve_target(target_alias: str, default_port: int = 65432):
    """
    Search the target alias in config.
    """
    aliases = load_config()

    if target_alias in aliases:
        host_info = aliases[target_alias]
        resolved_ip = host_info.get("hostname", target_alias)
        resolved_port = int(host_info.get("port", default_port))

        print(f"[*] Alias resolved: '{target_alias}' -> {resolved_ip}:{resolved_port}")
        return resolved_ip, resolved_port

    # If alias could not found, assume the input was a real ip
    return target_alias, default_port
