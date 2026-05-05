from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable


MAX_PORT = 65535


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


@dataclass(frozen=True)
class PortScanResult:
    port: int
    is_open: bool
    service: str | None = None


def parse_ports(raw_ports: str) -> list[int]:
    ports: set[int] = set()

    for token in raw_ports.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            start_raw, end_raw = token.split("-", 1)
            start, end = int(start_raw), int(end_raw)
            if start > end:
                raise ValueError(f"Intervalo de portas invalido: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))

    invalid = [port for port in ports if port < 1 or port > MAX_PORT]
    if invalid:
        raise ValueError(f"Porta fora do intervalo 1-{MAX_PORT}: {invalid[0]}")

    if not ports:
        raise ValueError("Informe pelo menos uma porta.")

    return sorted(ports)


def is_port_open(target: str, port: int, timeout: float = 0.7) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((target, port)) == 0


def scan_ports(target: str, ports: Iterable[int], timeout: float = 0.7) -> list[PortScanResult]:
    results: list[PortScanResult] = []

    for port in ports:
        if is_port_open(target, port, timeout):
            results.append(
                PortScanResult(
                    port=port,
                    is_open=True,
                    service=COMMON_SERVICES.get(port),
                )
            )

    return results
