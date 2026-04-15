
```

                                    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
                                    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
                                    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
                                    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
                                    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
                                    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                Network Recon & Vulnerability Scanner
                                             httpx · naabu · nmap · nuclei · brute-force

```

# 🔍 NetScan — Network Recon & Vulnerability Scanner

> **[Português](#português) | [English](#english)**

---

## Português

### Descrição

**NetScan** é um script Bash para reconhecimento de rede e varredura de vulnerabilidades em larga escala. Ele integra quatro ferramentas amplamente utilizadas em pentest e bug bounty — **httpx**, **naabu**, **nmap** e **nuclei** — em um pipeline automatizado de três etapas: Web Scan, Port Scan e Brute-Force de serviços.

### ✨ Funcionalidades

- **Web Scan** — Descobre hosts HTTP/HTTPS ativos e executa análise DAST com Nuclei
- **Port Scan** — Varredura rápida com naabu (top 1000 portas) + detecção de vulnerabilidades com nmap vulners + Nuclei
- **Brute-Force** — Ataque de força bruta via nmap em 17 serviços (SSH, FTP, MySQL, RDP, Redis, MongoDB e outros)
- Suporte a CIDR, IPs únicos e ranges de IP no arquivo de entrada
- Relatório final consolidado com contagem de findings por severidade
- Log completo de toda a execução salvo em arquivo
- Etapas configuráveis — cada fase pode ser ignorada individualmente

### 📋 Pré-requisitos

As seguintes ferramentas devem estar instaladas e disponíveis no `PATH`:

| Ferramenta | Instalação |
|---|---|
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nmap](https://nmap.org) | `apt install nmap` / `brew install nmap` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> **Nota:** O script continua mesmo se alguma ferramenta estiver ausente — a etapa correspondente é ignorada com um aviso.

### 🚀 Uso

```bash
chmod +x netscan.sh
./netscan.sh -i <arquivo> [opções]
```

#### Opções

| Flag | Descrição | Padrão |
|---|---|---|
| `-i <arquivo>` | Arquivo com blocos IP/CIDR **(obrigatório)** | — |
| `-o <dir>` | Diretório de saída | `./output_<timestamp>` |
| `-t <n>` | Threads do Nuclei | `200` |
| `-r <n>` | Rate limit do naabu (pacotes/s) | `10000` |
| `-s <lista>` | Severidades do Nuclei | `critical,high,medium,low` |
| `-S` | Pular etapa de brute-force | — |
| `-W` | Pular etapa web (httpx + nuclei) | — |
| `-N` | Pular etapa de port scan (naabu + nmap) | — |
| `-h` | Exibir ajuda | — |

#### Exemplos

```bash
# Varredura completa
./netscan.sh -i alvos.txt

# Sem brute-force
./netscan.sh -i alvos.txt -S

# Apenas brute-force (pula web e port scan)
./netscan.sh -i alvos.txt -W -N

# Personalizado: só crítico e alto, diretório específico
./netscan.sh -i alvos.txt -s critical,high -o /tmp/scan_cliente
```

### 📄 Formato do arquivo de entrada (`-i`)

```
# Comentários são ignorados
10.0.0.0/8               # Bloco CIDR
192.168.1.1              # IP único
172.16.0.1-172.16.0.50  # Range de IPs
```

### 📁 Estrutura de saída

```
output_<timestamp>/
├── web/
│   └── alive_web.txt          # Hosts HTTP/HTTPS ativos
├── ports/
│   ├── ports.txt              # host:porta descobertos
│   └── hosts_only.txt         # IPs únicos
├── nmap/
│   ├── nmap_vuln.log          # Resultado do nmap vulners
│   └── nmap_brute.log         # Resultado consolidado do brute-force
├── nuclei/
│   ├── web_vuln.log           # Findings nuclei (web)
│   ├── cidr_vuln.log          # Findings nuclei (CIDR/portas)
│   └── all_findings.txt       # Todos os findings unificados
├── brute/
│   ├── brute_ports.txt        # Portas de serviço abertas
│   └── brute_port_<N>.log     # Log por serviço/porta
└── logs/
    ├── pipeline_<timestamp>.log  # Log completo da execução
    ├── httpx.log
    ├── naabu.log
    ├── nuclei_web.log
    └── ...
```

### ⚠️ Aviso Legal

> Este script foi desenvolvido exclusivamente para uso em ambientes **autorizados** — pentest contratado, bug bounty com escopo definido, laboratórios próprios ou redes sob sua administração. O uso não autorizado contra sistemas de terceiros é **ilegal**. O autor não se responsabiliza por qualquer uso indevido.

---

## English

### Description

**NetScan** is a Bash script for large-scale network reconnaissance and vulnerability scanning. It integrates four widely used pentesting and bug bounty tools — **httpx**, **naabu**, **nmap**, and **nuclei** — into an automated three-stage pipeline: Web Scan, Port Scan, and Service Brute-Force.

### ✨ Features

- **Web Scan** — Discovers live HTTP/HTTPS hosts and runs DAST analysis with Nuclei
- **Port Scan** — Fast scanning with naabu (top 1000 ports) + vulnerability detection with nmap vulners + Nuclei
- **Brute-Force** — nmap-based credential brute-forcing for 17 services (SSH, FTP, MySQL, RDP, Redis, MongoDB, and more)
- Supports CIDR blocks, single IPs, and IP ranges in the input file
- Final consolidated report with findings count per severity level
- Full execution log saved to file
- Configurable stages — each phase can be skipped individually

### 📋 Requirements

The following tools must be installed and available in your `PATH`:

| Tool | Installation |
|---|---|
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nmap](https://nmap.org) | `apt install nmap` / `brew install nmap` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> **Note:** The script continues even if a tool is missing — the corresponding stage is skipped with a warning.

### 🚀 Usage

```bash
chmod +x netscan.sh
./netscan.sh -i <file> [options]
```

#### Options

| Flag | Description | Default |
|---|---|---|
| `-i <file>` | File with IP/CIDR blocks **(required)** | — |
| `-o <dir>` | Output directory | `./output_<timestamp>` |
| `-t <n>` | Nuclei threads | `200` |
| `-r <n>` | naabu rate limit (packets/s) | `10000` |
| `-s <list>` | Nuclei severities | `critical,high,medium,low` |
| `-S` | Skip brute-force stage | — |
| `-W` | Skip web stage (httpx + nuclei) | — |
| `-N` | Skip port scan stage (naabu + nmap) | — |
| `-h` | Show help | — |

#### Examples

```bash
# Full scan
./netscan.sh -i targets.txt

# Without brute-force
./netscan.sh -i targets.txt -S

# Brute-force only (skip web and port scan)
./netscan.sh -i targets.txt -W -N

# Custom: critical and high only, specific output directory
./netscan.sh -i targets.txt -s critical,high -o /tmp/client_scan
```

### 📄 Input File Format (`-i`)

```
# Comments are ignored
10.0.0.0/8               # CIDR block
192.168.1.1              # Single IP
172.16.0.1-172.16.0.50  # IP range
```

### 📁 Output Structure

```
output_<timestamp>/
├── web/
│   └── alive_web.txt          # Live HTTP/HTTPS hosts
├── ports/
│   ├── ports.txt              # Discovered host:port pairs
│   └── hosts_only.txt         # Unique IPs
├── nmap/
│   ├── nmap_vuln.log          # nmap vulners output
│   └── nmap_brute.log         # Consolidated brute-force results
├── nuclei/
│   ├── web_vuln.log           # Nuclei findings (web)
│   ├── cidr_vuln.log          # Nuclei findings (CIDR/ports)
│   └── all_findings.txt       # All findings merged
├── brute/
│   ├── brute_ports.txt        # Open service ports
│   └── brute_port_<N>.log     # Per-service/port log
└── logs/
    ├── pipeline_<timestamp>.log  # Full execution log
    ├── httpx.log
    ├── naabu.log
    ├── nuclei_web.log
    └── ...
```

### ⚠️ Legal Disclaimer

> This script was developed exclusively for use in **authorized** environments — contracted penetration testing, bug bounty programs with a defined scope, personal labs, or networks under your administration. Unauthorized use against third-party systems is **illegal**. The author assumes no responsibility for any misuse.

---

<p align="center">Made with 🔒 for ethical security testing</p>
