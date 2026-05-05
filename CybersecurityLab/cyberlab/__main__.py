from __future__ import annotations

import argparse
import sys

from .brute_force import BruteForceResult, run_dictionary_attack
from .scanner import PortScanResult, parse_ports, scan_ports
from .vuln_detector import analyze_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberlab",
        description="Ferramentas educacionais de ciberseguranca para ambientes autorizados.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Escaneia portas TCP.")
    scan.add_argument("target", help="Host ou IP autorizado. Ex: 127.0.0.1")
    scan.add_argument("--ports", default="1-1024", help="Portas. Ex: 22,80,443 ou 20-25")
    scan.add_argument("--timeout", type=float, default=0.7, help="Timeout por porta em segundos.")

    vuln = subparsers.add_parser("vuln", help="Procura sinais simples de risco.")
    vuln.add_argument("target", help="Host ou IP autorizado. Ex: 127.0.0.1")
    vuln.add_argument("--ports", default="21,22,23,25,80,110,139,143,443,445,3306,3389,5432,6379,8080")
    vuln.add_argument("--timeout", type=float, default=0.7)

    brute = subparsers.add_parser("brute-force", help="Simula brute force contra hash local.")
    brute.add_argument("--password", required=True, help="Senha alvo do laboratorio.")
    brute.add_argument("--wordlist", required=True, help="Arquivo com uma palavra por linha.")
    brute.add_argument("--salt", default="cyberlab", help="Salt usado no hash local.")

    return parser


def render_scan(results: list[PortScanResult]) -> str:
    if not results:
        return "Nenhuma porta aberta encontrada."

    lines = ["Portas abertas:"]
    for result in results:
        service = f" ({result.service})" if result.service else ""
        lines.append(f"- {result.port}/tcp{service}")
    return "\n".join(lines)


def render_brute_force(result: BruteForceResult) -> str:
    if result.found:
        return (
            "Senha encontrada no laboratorio!\n"
            f"- senha: {result.password}\n"
            f"- tentativas: {result.attempts}\n"
            f"- tempo: {result.elapsed_seconds:.4f}s"
        )
    return (
        "Senha nao encontrada na wordlist.\n"
        f"- tentativas: {result.attempts}\n"
        f"- tempo: {result.elapsed_seconds:.4f}s"
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            ports = parse_ports(args.ports)
            print(render_scan(scan_ports(args.target, ports, args.timeout)))
            return 0

        if args.command == "vuln":
            ports = parse_ports(args.ports)
            report = analyze_target(args.target, ports, args.timeout)
            print(report.to_text())
            return 0

        if args.command == "brute-force":
            result = run_dictionary_attack(args.password, args.wordlist, args.salt)
            print(render_brute_force(result))
            return 0
    except (OSError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
