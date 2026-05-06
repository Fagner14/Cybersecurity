Laboratório de Segurança Cibernética
Projeto educacional em Python com três ferramentas simples:

Scanner de portas TCP para alvos autorizados.
Detector básico de possíveis vulnerabilidades por porta/banner.
Simulador de força bruta contra um hash local, sem atacar serviços reais.
Use apenas em ambientes próprios, laboratórios ou alvos onde você tem autorização explícita.

Requisitos
Python 3.10+
Nenhuma dependência externa.
Como usar
Entre na pasta do projeto:

cd cybersecurity_lab
Scanner de:

python -m cyberlab scan 127.0.0.1 --ports 20-25,80,443 --timeout 0.5
Detector simples:

python -m cyberlab vuln 127.0.0.1 --ports 21,22,23,80,443
Simulador de força bruta:

python -m cyberlab brute-force --password senha123 --wordlist wordlists/common.txt
Rodar os testes:

python -m unittest discover tests
Estrutura
cybersecurity_lab/
  cyberlab/
    __main__.py
    brute_force.py
    scanner.py
    vuln_detector.py
  tests/
  wordlists/
Observacao sobre seguranca
O módulo de força bruta e propositalmente um simulador: ele cria um hash SHA-256 local para uma senha informada e testa palavras contra esse hash. Ele não se conecta a SSH, HTTP, bancos de dados ou qualquer outro serviço.
