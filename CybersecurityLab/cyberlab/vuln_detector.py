from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Iterable

from .scanner import COMMON_SERVICES, PortScanResult, scan_ports

try:
    import ssl
except ImportError:
    ssl = None


RISK_RULES = {
    21: ("medio", "FTP costuma trafegar credenciais sem criptografia."),
    23: ("alto", "Telnet nao criptografa a sessao e deve ser evitado."),
    25: ("baixo", "SMTP exposto exige configuracao cuidadosa contra relay aberto."),
    80: ("baixo", "HTTP sem TLS pode expor dados sensiveis em transito."),
    445: ("medio", "SMB exposto fora da rede local aumenta a superficie de ataque."),
    3306: ("medio", "MySQL exposto deve exigir rede restrita e senhas fortes."),
    3389: ("medio", "RDP exposto deve usar MFA, VPN ou allowlist."),
    5432: ("medio", "PostgreSQL exposto deve ter acesso restrito por rede."),
    6379: ("alto", "Redis exposto sem autenticacao e uma falha comum e grave."),
}


@dataclass(frozen=True)
class Finding:
    port: int
    severity: str
    title: str
    evidence: str
    recommendation: str


@dataclass
class VulnerabilityReport:
    target: str
    open_ports: list[PortScanResult]
    findings: list[Finding] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [f"Relatorio para {self.target}"]

        if self.open_ports:
            lines.append("\nPortas abertas:")
            for result in self.open_ports:
                service = result.service or COMMON_SERVICES.get(result.port) or "desconhecido"
                lines.append(f"- {result.port}/tcp ({service})")
        else:
            lines.append("\nNenhuma porta aberta encontrada nas portas analisadas.")

        if self.findings:
            lines.append("\nPossiveis riscos:")
            for finding in self.findings:
                lines.append(
                    f"- [{finding.severity.upper()}] porta {finding.port}: {finding.title}\n"
                    f"  evidencia: {finding.evidence}\n"
                    f"  recomendacao: {finding.recommendation}"
                )
        else:
            lines.append("\nNenhum risco simples identificado.")

        return "\n".join(lines)


def grab_banner(target: str, port: int, timeout: float = 0.7) -> str:
    try:
        if port == 443 and ssl is not None:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                    tls_sock.settimeout(timeout)
                    return tls_sock.version() or "TLS ativo"

        if port == 443 and ssl is None:
            return "TLS possivelmente ativo, mas modulo ssl indisponivel neste ambiente."

        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in {80, 8080}:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(120)
            return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def analyze_open_port(target: str, result: PortScanResult, timeout: float = 0.7) -> list[Finding]:
    findings: list[Finding] = []
    banner = grab_banner(target, result.port, timeout)

    if result.port in RISK_RULES:
        severity, message = RISK_RULES[result.port]
        findings.append(
            Finding(
                port=result.port,
                severity=severity,
                title=message,
                evidence=banner or "porta aberta",
                recommendation="Restrinja acesso por rede, habilite criptografia/autenticacao forte e desative se nao for necessario.",
            )
        )

    lower_banner = banner.lower()
    if "apache/2.2" in lower_banner or "openssh_7." in lower_banner:
        findings.append(
            Finding(
                port=result.port,
                severity="medio",
                title="Banner sugere versao antiga de software.",
                evidence=banner,
                recommendation="Verifique a versao instalada e aplique atualizacoes de seguranca.",
            )
        )

    return findings


def analyze_target(target: str, ports: Iterable[int], timeout: float = 0.7) -> VulnerabilityReport:
    open_ports = scan_ports(target, ports, timeout)
    findings: list[Finding] = []

    for result in open_ports:
        findings.extend(analyze_open_port(target, result, timeout))

    return VulnerabilityReport(target=target, open_ports=open_ports, findings=findings)
