# Cybersecurity Lab

Projeto educacional em Python com tres ferramentas simples:

- Scanner de portas TCP para alvos autorizados.
- Detector basico de possiveis vulnerabilidades por porta/banner.
- Simulador de brute force contra um hash local, sem atacar servicos reais.

> Use apenas em ambientes proprios, laboratorios ou alvos onde voce tem autorizacao explicita.

## Requisitos

- Python 3.10+
- Nenhuma dependencia externa.

## Como usar

Entre na pasta do projeto:

```powershell
cd cybersecurity_lab
```

Scanner de portas:

```powershell
python -m cyberlab scan 127.0.0.1 --ports 20-25,80,443 --timeout 0.5
```

Detector simples:

```powershell
python -m cyberlab vuln 127.0.0.1 --ports 21,22,23,80,443
```

Simulador de brute force:

```powershell
python -m cyberlab brute-force --password senha123 --wordlist wordlists/common.txt
```

Rodar os testes:

```powershell
python -m unittest discover tests
```

## Estrutura

```text
cybersecurity_lab/
  cyberlab/
    __main__.py
    brute_force.py
    scanner.py
    vuln_detector.py
  tests/
  wordlists/
```

## Observacao sobre seguranca

O modulo de brute force e propositalmente um simulador: ele cria um hash SHA-256 local para uma senha informada e testa palavras contra esse hash. Ele nao se conecta a SSH, HTTP, bancos de dados ou qualquer outro servico.
