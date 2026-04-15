#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

CIDR_FILE=""
OUTPUT_DIR=""
NUCLEI_THREADS=200
NAABU_RATE=10000
SEVERITIES="critical,high,medium,low"
SKIP_BRUTE=false
SKIP_WEB=false
SKIP_NMAP=false
START_TS=$(date +%Y%m%d_%H%M%S)

banner() {
  echo -e "${CYAN}${BOLD}"
  cat << 'EOF'
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
  echo -e "${RESET}"
  echo -e "${BLUE}            Network Recon & Vulnerability Scanner${RESET}"
  echo -e "${BLUE}       httpx · naabu · nmap · nuclei · brute-force${RESET}"
  echo ""
}

usage() {
  banner
  echo -e "  ${BOLD}Uso:${RESET} ./network_scan.sh -i <arquivo> [opções]"
  echo ""
  echo -e "  ${BOLD}Opções:${RESET}"
  echo -e "    ${CYAN}-i${RESET}  Arquivo com blocos IP/CIDR      ${BOLD}(obrigatório)${RESET}"
  echo -e "    ${CYAN}-o${RESET}  Diretório de saída              (padrão: ./output_<timestamp>)"
  echo -e "    ${CYAN}-t${RESET}  Threads nuclei                  (padrão: 200)"
  echo -e "    ${CYAN}-r${RESET}  Rate limit naabu (pkts/s)       (padrão: 10000)"
  echo -e "    ${CYAN}-s${RESET}  Severidades nuclei              (padrão: critical,high,medium,low)"
  echo -e "    ${CYAN}-S${RESET}  Pular etapa de brute-force"
  echo -e "    ${CYAN}-W${RESET}  Pular etapa web (httpx+nuclei)"
  echo -e "    ${CYAN}-N${RESET}  Pular etapa nmap vuln"
  echo -e "    ${CYAN}-h${RESET}  Exibe esta ajuda"
  echo ""
  echo -e "  ${BOLD}Exemplos:${RESET}"
  echo -e "    ${CYAN}./network_scan.sh -i blocos.txt${RESET}"
  echo -e "    ${CYAN}./network_scan.sh -i blocos.txt -S${RESET}         (sem brute-force)"
  echo -e "    ${CYAN}./network_scan.sh -i blocos.txt -W -N${RESET}      (só brute-force)"
  echo ""
  echo -e "  ${BOLD}Formato do arquivo (-i):${RESET}"
  echo -e "    10.0.0.0/8               → bloco CIDR"
  echo -e "    192.168.1.1              → IP único"
  echo -e "    172.16.0.1-172.16.0.50  → range de IPs"
  echo -e "    # comentários são ignorados"
  echo ""
  exit 0
}

info()    { echo -e "${GREEN}[+]${RESET} $(date '+%H:%M:%S') $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $(date '+%H:%M:%S') $*"; }
error()   { echo -e "${RED}[-]${RESET} $(date '+%H:%M:%S') $*" >&2; }
step()    { echo -e "\n${BLUE}${BOLD}┌─[ $* ]${RESET}\n"; }
done_step(){ echo -e "${GREEN}${BOLD}└─[ DONE ]${RESET} $*\n"; }
die()     { error "$*"; exit 1; }

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "Ferramenta não encontrada: '${BOLD}$1${RESET}' — etapa será ignorada."
    return 1
  fi
  return 0
}

count_lines() { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }

elapsed() {
  local secs=$(( $(date +%s) - START_EPOCH ))
  printf '%02dh:%02dm:%02ds' $((secs/3600)) $((secs%3600/60)) $((secs%60))
}

validate_cidr() {
  echo "$1" | grep -qE \
    '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$|^([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

while getopts ":i:o:t:r:s:SWNh" opt; do
  case $opt in
    i) CIDR_FILE="$OPTARG"      ;;
    o) OUTPUT_DIR="$OPTARG"     ;;
    t) NUCLEI_THREADS="$OPTARG" ;;
    r) NAABU_RATE="$OPTARG"     ;;
    s) SEVERITIES="$OPTARG"     ;;
    S) SKIP_BRUTE=true           ;;
    W) SKIP_WEB=true             ;;
    N) SKIP_NMAP=true            ;;
    h) usage                     ;;
    :) die "Opção -$OPTARG requer argumento." ;;
    \?) die "Opção inválida: -$OPTARG" ;;
  esac
done

banner

if [[ -z "$CIDR_FILE" ]]; then
  error "Arquivo de blocos IP não informado."
  echo -e "  Use: ${BOLD}./network_scan.sh -i <arquivo>${RESET}"
  echo -e "  Ex:  ${CYAN}./network_scan.sh -i blocos.txt${RESET}"
  echo ""
  exit 1
fi

[[ -f "$CIDR_FILE" ]] || die "Arquivo não encontrado: $CIDR_FILE"
[[ -s "$CIDR_FILE" ]] || die "Arquivo vazio: $CIDR_FILE"

TEMP="./cidr_validated_${START_TS}.txt"
VALID=0; INVALID=0

while IFS= read -r LINE || [[ -n "$LINE" ]]; do
  LINE=$(echo "$LINE" | tr -d '[:space:]')
  [[ -z "$LINE" || "$LINE" =~ ^# ]] && continue
  if validate_cidr "$LINE"; then
    echo "$LINE" >> "$TEMP"
    VALID=$((VALID + 1))
  else
    warn "Ignorado (inválido): $LINE"
    INVALID=$((INVALID + 1))
  fi
done < "$CIDR_FILE"

[[ "$VALID" -eq 0 ]] && die "Nenhuma entrada válida em $CIDR_FILE"

info "$VALID bloco(s) carregado(s).$( [[ $INVALID -gt 0 ]] && echo " $INVALID ignorado(s)." || echo "")"
echo ""
echo -e "  ${BOLD}Alvos (${VALID} bloco(s)):${RESET}"
while IFS= read -r ENTRY; do
  echo -e "    ${CYAN}•${RESET} $ENTRY"
done < "$TEMP"
echo ""

CIDR_FILE="$TEMP"

OUTPUT_DIR="${OUTPUT_DIR:-./output_${START_TS}}"
mkdir -p "$OUTPUT_DIR"/{web,ports,nmap,nuclei,brute,logs}

LOG_FILE="$OUTPUT_DIR/logs/pipeline_${START_TS}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

START_EPOCH=$(date +%s)

WEB_ALIVE="$OUTPUT_DIR/web/alive_web.txt"
WEB_VULN="$OUTPUT_DIR/nuclei/web_vuln.log"
PORTS_FILE="$OUTPUT_DIR/ports/ports.txt"
NMAP_VULN="$OUTPUT_DIR/nmap/nmap_vuln.log"
NMAP_BRUTE="$OUTPUT_DIR/nmap/nmap_brute.log"
CIDR_VULN="$OUTPUT_DIR/nuclei/cidr_vuln.log"

echo -e "${BOLD}Configuração do Scan:${RESET}"
echo -e "  Alvos:          ${CYAN}$CIDR_FILE${RESET} ($(count_lines "$CIDR_FILE") blocos)"
echo -e "  Saída:          ${CYAN}$OUTPUT_DIR${RESET}"
echo -e "  Nuclei threads: $NUCLEI_THREADS"
echo -e "  Naabu rate:     $NAABU_RATE pps"
echo -e "  Severidades:    $SEVERITIES"
echo -e "  Web Scan:       $( [[ "$SKIP_WEB"   == false ]] && echo "${GREEN}ativo${RESET}" || echo "${YELLOW}ignorado${RESET}")"
echo -e "  Port Scan:      $( [[ "$SKIP_NMAP"  == false ]] && echo "${GREEN}ativo${RESET}" || echo "${YELLOW}ignorado${RESET}")"
echo -e "  Brute-Force:    $( [[ "$SKIP_BRUTE" == false ]] && echo "${GREEN}ativo${RESET}" || echo "${YELLOW}ignorado${RESET}")"
echo -e "  Log:            $LOG_FILE"
echo ""

step "Verificando ferramentas"
for tool in httpx naabu nmap nuclei; do
  check_tool "$tool" && info "$tool ✔" || true
done

# =============================================================================
#  ETAPA 1 — Web Scan
# =============================================================================
if [[ "$SKIP_WEB" == false ]]; then
  step "Etapa 1/3 — Web Scan: httpx + Nuclei (portas web)"

  if check_tool httpx && check_tool nuclei; then

    info "Descobrindo hosts web ativos (80, 443, 8080, 8443, 8888)..."
    httpx \
      -l "$CIDR_FILE" \
      -ports 80,443,8080,8443,8888 \
      -no-fallback \
      -mc 200,204,301,302,307,401,403 \
      -t 2000 \
      -rl 300 \
      -timeout 10 \
      -retries 2 \
      -silent \
      -o "$WEB_ALIVE" \
      2>>"$OUTPUT_DIR/logs/httpx.log" || true

    ALIVE=$(count_lines "$WEB_ALIVE")
    info "Hosts web ativos: ${BOLD}$ALIVE${RESET}"

    if [[ "$ALIVE" -gt 0 ]]; then
      info "Executando Nuclei DAST nos hosts web..."
      nuclei \
        -l "$WEB_ALIVE" \
        -s "$SEVERITIES" \
        -c "$NUCLEI_THREADS" \
        -bs 150 \
        -rl 300 \
        -timeout 10 \
        -retries 2 \
        -stats \
        -o "$WEB_VULN" \
        2>>"$OUTPUT_DIR/logs/nuclei_web.log" || true

      info "Nuclei Web: ${BOLD}$(count_lines "$WEB_VULN") findings${RESET} → $WEB_VULN"
    else
      warn "Nenhum host web ativo. Pulando Nuclei web."
    fi

    done_step "Web Scan concluído (elapsed: $(elapsed))"
  else
    warn "httpx ou nuclei ausentes — etapa web ignorada."
  fi
else
  warn "Etapa Web ignorada (-W)."
fi

# =============================================================================
#  ETAPA 2 — Port Scan
# =============================================================================
if [[ "$SKIP_NMAP" == false ]]; then
  step "Etapa 2/3 — Port Scan: naabu + nmap vulners + Nuclei"

  if check_tool naabu; then

    info "Executando naabu (top 1000 portas)..."
    naabu \
      -list "$CIDR_FILE" \
      -verify \
      -rate "$NAABU_RATE" \
      -retries 2 \
      -top-ports 1000 \
      -c 300 \
      -timeout 5 \
      -silent \
      -o "$PORTS_FILE" \
      2>>"$OUTPUT_DIR/logs/naabu.log" || true

    PORTS_FOUND=$(count_lines "$PORTS_FILE")
    info "Hosts:portas descobertos: ${BOLD}$PORTS_FOUND${RESET}"

    if [[ "$PORTS_FOUND" -gt 0 ]] && check_tool nmap; then
      info "Executando nmap com script vulners..."

      awk -F: '{print $1}' "$PORTS_FILE" | sort -u \
        > "$OUTPUT_DIR/ports/hosts_only.txt"
      PORTS_LIST=$(awk -F: '{print $2}' "$PORTS_FILE" | sort -un | paste -sd,)

      nmap \
        -sV \
        --script vulners \
        -p "$PORTS_LIST" \
        -Pn \
        --open \
        -T4 \
        --min-hostgroup 64 \
        --min-parallelism 100 \
        -iL "$OUTPUT_DIR/ports/hosts_only.txt" \
        -oN "$NMAP_VULN" \
        2>>"$OUTPUT_DIR/logs/nmap_vuln.log" || true

      info "nmap vulners → $NMAP_VULN"
    fi

    if [[ "$PORTS_FOUND" -gt 0 ]] && check_tool nuclei; then
      info "Executando Nuclei nos hosts:portas descobertos..."
      nuclei \
        -l "$PORTS_FILE" \
        -s "$SEVERITIES" \
        -c "$NUCLEI_THREADS" \
        -bs 150 \
        -rl 300 \
        -timeout 10 \
        -retries 2 \
        -stats \
        -o "$CIDR_VULN" \
        2>>"$OUTPUT_DIR/logs/nuclei_cidr.log" || true

      info "Nuclei CIDR: ${BOLD}$(count_lines "$CIDR_VULN") findings${RESET} → $CIDR_VULN"
    fi

    done_step "Port Scan concluído (elapsed: $(elapsed))"
  else
    warn "naabu ausente — etapa de port scan ignorada."
  fi
else
  warn "Etapa Port Scan ignorada (-N)."
fi

# =============================================================================
#  ETAPA 3 — Brute-Force
# =============================================================================
if [[ "$SKIP_BRUTE" == false ]]; then
  step "Etapa 3/3 — Brute-Force de Serviços"

  declare -A BRUTE_MAP=(
    [21]="ftp-brute"
    [22]="ssh-brute"
    [23]="telnet-brute"
    [25]="smtp-brute"
    [110]="pop3-brute"
    [143]="imap-brute"
    [161]="snmp-brute"
    [389]="ldap-brute"
    [445]="smb-brute"
    [993]="imap-brute"
    [1433]="ms-sql-brute"
    [1521]="oracle-brute"
    [3306]="mysql-brute"
    [5432]="pgsql-brute"
    [5900]="vnc-brute"
    [6379]="redis-brute"
    [27017]="mongodb-brute"
  )

  BRUTE_PORTS=$(IFS=,; echo "${!BRUTE_MAP[*]}")
  BRUTE_PORTS_FILE="$OUTPUT_DIR/brute/brute_ports.txt"

  if check_tool naabu; then

    info "Descobrindo portas de serviços abertas: $BRUTE_PORTS"
    naabu \
      -list "$CIDR_FILE" \
      -verify \
      -rate "$NAABU_RATE" \
      -retries 2 \
      -p "$BRUTE_PORTS" \
      -c 300 \
      -timeout 5 \
      -silent \
      -o "$BRUTE_PORTS_FILE" \
      2>>"$OUTPUT_DIR/logs/naabu_brute.log" || true

    BRUTE_FOUND=$(count_lines "$BRUTE_PORTS_FILE")
    info "Hosts com serviços brute-forçáveis: ${BOLD}$BRUTE_FOUND${RESET}"

    if [[ "$BRUTE_FOUND" -gt 0 ]] && check_tool nmap; then
      for PORT in "${!BRUTE_MAP[@]}"; do
        SCRIPT="${BRUTE_MAP[$PORT]}"
        HOSTS_FOR_PORT="$OUTPUT_DIR/brute/hosts_port_${PORT}.txt"

        grep ":${PORT}$" "$BRUTE_PORTS_FILE" \
          | awk -F: '{print $1}' \
          | sort -u > "$HOSTS_FOR_PORT" 2>/dev/null || true

        if [[ -s "$HOSTS_FOR_PORT" ]]; then
          info "Brute-force porta ${BOLD}$PORT${RESET} ($SCRIPT) — $(count_lines "$HOSTS_FOR_PORT") host(s)..."
          nmap \
            -sV \
            --script "$SCRIPT" \
            -p "$PORT" \
            -Pn \
            -T4 \
            --open \
            --min-hostgroup 32 \
            -iL "$HOSTS_FOR_PORT" \
            -oN "$OUTPUT_DIR/brute/brute_port_${PORT}.log" \
            2>>"$OUTPUT_DIR/logs/nmap_brute.log" || true
        fi
      done

      cat "$OUTPUT_DIR/brute/brute_port_"*.log > "$NMAP_BRUTE" 2>/dev/null || true
      info "Brute-force consolidado → $NMAP_BRUTE"
    fi

    done_step "Brute-force concluído (elapsed: $(elapsed))"
  else
    warn "naabu ausente — etapa brute-force ignorada."
  fi
else
  warn "Etapa Brute-Force ignorada (-S)."
fi

# =============================================================================
#  Relatório Final
# =============================================================================
step "Relatório Final"

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║                  RESUMO DE RESULTADOS               ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
printf "  %-35s %s\n" "Alvos escaneados:"       "$(count_lines "$CIDR_FILE") blocos IP/CIDR"
printf "  %-35s %s\n" "Tempo total:"            "$(elapsed)"
echo ""
echo -e "  ${CYAN}${BOLD}── Web ──────────────────────────────────────────${RESET}"
printf "  %-35s %s\n" "Hosts web ativos:"       "$(count_lines "$WEB_ALIVE")"
printf "  %-35s %s\n" "Findings web (nuclei):"  "$(count_lines "$WEB_VULN")"
echo ""
echo -e "  ${CYAN}${BOLD}── Ports / CIDR ─────────────────────────────────${RESET}"
printf "  %-35s %s\n" "Hosts:portas abertos:"   "$(count_lines "$PORTS_FILE")"
printf "  %-35s %s\n" "Findings CIDR (nuclei):" "$(count_lines "$CIDR_VULN")"
printf "  %-35s %s\n" "Nmap vulners log:"       "$NMAP_VULN"
echo ""
echo -e "  ${CYAN}${BOLD}── Brute-Force ──────────────────────────────────${RESET}"
printf "  %-35s %s\n" "Nmap brute log:"         "$NMAP_BRUTE"
echo ""
echo -e "  ${CYAN}${BOLD}── Saída ────────────────────────────────────────${RESET}"
printf "  %-35s %s\n" "Diretório completo:"     "$OUTPUT_DIR"
printf "  %-35s %s\n" "Log pipeline:"           "$LOG_FILE"
echo ""

COMBINED="$OUTPUT_DIR/nuclei/all_findings.txt"
cat "$WEB_VULN" "$CIDR_VULN" 2>/dev/null | sort -u > "$COMBINED" || true

if [[ -s "$COMBINED" ]]; then
  echo -e "  ${BOLD}Findings por severidade:${RESET}"
  for sev in critical high medium low info; do
    COUNT=$(grep -ic "\[$sev\]" "$COMBINED" 2>/dev/null || echo 0)
    [[ "$COUNT" -gt 0 ]] && printf "  %-35s %s\n" "  [$sev]:" "$COUNT"
  done
  echo ""
fi

echo -e "${GREEN}${BOLD}  Scan finalizado com sucesso! $(date)${RESET}"
echo ""
