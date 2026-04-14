#!/bin/bash

#INFO on windows, use `dos2unix netscan.sh` after each change

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

TIMEOUT=1100
MAX_JOBS=60
HOSTNAME=true
INTERFACE=""
RETRY=2
OUTPUT=""
NOPROGRESS=false
NOCOLOR=false
MODE="ICMP"
FORCED=false
EXCLUDE=""
TARGET_TYPE=""
TARGET_IPS=()

SINGLE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
RANGE='^([0-9]{1,3}(\-[0-9]{1,3})?\.){3}[0-9]{1,3}(\-[0-9]{1,3})?$'
EXCL_CIDR='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
LIST='^([0-9]{1,3}\.){3}[0-9]{1,3}(,([0-9]{1,3}\.){3}[0-9]{1,3})*$'

ALIVE_FILE=$(mktemp) || exit 1
DONE_FILE=$(mktemp) || exit 1

FIFO="/tmp/netscan_fifo"
mkfifo "$FIFO"
exec 3<>"$FIFO"
rm "$FIFO"

for ((i = 0; i < MAX_JOBS; i++)); do
  echo >&3
done

figlet -f smslant "NETscan" -t

check_deps() {
  local missing=()
  if command -v arping >/dev/null 2>&1; then
    if ! arping --help | grep -q "Thomas"; then
      echo "Wrong version of arping installed, you need the one by Thomas Habets"
      exit 1
    fi
  fi

  command -v fping &>/dev/null || missing+=("fping")
  command -v arping &>/dev/null || missing+=("arping (Thomas Habets)")
  command -v dig &>/dev/null || missing+=("dig (dnsutils / bind-utils)")
  command -v ip &>/dev/null || missing+=("ip (iproute2)")

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}Error:${RESET} Missing dependencies:"
    for dep in "${missing[@]}"; do
      echo -e "  - $dep"
    done
    exit 1
  fi
}

echo -e $BANNER
check_deps

cleanup() {

  if [[ -n "$CLEANED" ]]; then
    return
  fi
  CLEANED=1

  if ! $NOPROGRESS; then
    kill $PROGRESS_PID 2>/dev/null
    wait $PROGRESS_PID 2>/dev/null
  fi
  JOBS=$(jobs -p)
  if [ -n "$JOBS" ]; then
    kill $JOBS 2>/dev/null
    wait $JOBS 2>/dev/null
  fi

  rm -f "$ALIVE_FILE" "$DONE_FILE"

  echo -ne "\r\033[K"

  if $INTERRUPTED; then
    echo -e "${YELLOW}Scan interrupted!${RESET}"
    exit 1
  fi
}

INTERRUPTED=false
trap 'INTERRUPTED=true; cleanup' SIGINT
trap cleanup EXIT

int_to_ip() {
  local int=$1
  printf "%d.%d.%d.%d\n" $(((int >> 24) & 255)) $(((int >> 16) & 255)) $(((int >> 8) & 255)) $((int & 255))
}

ip_to_int() {
  local i1=$1 i2=$2 i3=$3 i4=$4

  printf "%d\n" $(((i1 << 24) + (i2 << 16) + (i3 << 8) + i4))
}

cidr2mask() {
  local i mask="" full_octets partial_octet
  local cidr="${1:-24}"
  cidr="${cidr//[!0-9]/}"

  full_octets=$((cidr / 8))
  partial_octet=$((cidr % 8))

  for ((i = 0; i < 4; i++)); do
    if [ $i -lt $full_octets ]; then
      mask+=255
    elif [ $i -eq $full_octets ]; then
      mask+=$((256 - 2 ** (8 - partial_octet)))
    else
      mask+=0
    fi
    [ $i -lt 3 ] && mask+="."
  done
  echo "$mask"
}

LOCAL_IP=$(ip -o -4 addr show ${INTERFACE:+dev $INTERFACE} | awk -F '[ /]+' '/global/ {print $4}' | head -n1)
if [[ -z "$LOCAL_IP" ]]; then
  echo -e "${RED}Error:${RESET} Could not detect local IP."
  exit 1
fi
IFS="." read -r l1 l2 l3 l4 <<<"$LOCAL_IP"
LOCAL_IP_INT=$(ip_to_int $l1 $l2 $l3 $l4)
LOCAL_CIDR=$(ip -o -f inet addr show ${INTERFACE:+dev $INTERFACE} | awk '/scope global/ {split($4, s, "/"); print s[2]}' | head -n1)
LOCAL_MASK=$(cidr2mask $LOCAL_CIDR)
IFS="." read -r y1 y2 y3 y4 <<<"$LOCAL_MASK"
local_mask_int=$(((y1 << 24) + (y2 << 16) + (y3 << 8) + y4))
local_network=$((LOCAL_IP_INT & local_mask_int))

is_local_ip() {
  local ip_int=$1
  [[ $((ip_int & local_mask_int)) -eq "$local_network" ]]
}

if [[ "$MODE" == "ARP" && $EUID -ne 0 ]]; then
  echo -e "${YELLOW}Warning:${RESET} ARP requires root, switching to ICMP!"
  MODE="ICMP"
fi

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error:${RESET} This script must be run as root."
  exit 1
fi

help() {
  echo -e "${BOLD}${BLUE}Usage:${RESET} $0 <TARGET> [OPTIONS]"
  echo ""
  echo -e "${BOLD}Arguments:${RESET}"
  echo -e "  ${CYAN}<TARGET>${RESET}                  Hosts to scan:"
  echo -e "                              CIDR:    ${YELLOW}192.168.1.0/24${RESET}"
  echo -e "                              Single:  ${YELLOW}192.168.1.1${RESET}"
  echo -e "                              Range:   ${YELLOW}192.168.1-10.1-20${RESET}"
  echo -e "                              List:    ${YELLOW}192.168.1.1,192.168.1.5${RESET}"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo -e "  ${CYAN}-t, --timeout <ms>${RESET}        Ping timeout in milliseconds (default: 1100)"
  echo -e "  ${CYAN}-j, --max-jobs <n>${RESET}        Max parallel jobs (default: 60)"
  echo -e "  ${CYAN}-i, --interface <iface>${RESET}   Network interface to use (ex: eth0, wlan0)"
  echo -e "  ${CYAN}-r, --retry <n>${RESET}           Number of ping retries (default: 2)"
  echo -e "  ${CYAN}-o, --output <file>${RESET}       Save results to CSV file (ex: results.csv)"
  echo -e "  ${CYAN}-e, --exclude <target>${RESET}    Exclude IPs from scan (same formats as TARGET)"
  echo -e "  ${CYAN}-H, --no-hostname${RESET}         Skip hostname resolution (faster)"
  echo -e "  ${CYAN}    --no-color${RESET}            Disable colored output"
  echo -e "  ${CYAN}    --no-progress${RESET}         Disable progress bar"
  echo -e "  ${CYAN}    --icmp${RESET}                Force ICMP mode"
  echo -e "  ${CYAN}    --arp${RESET}                 Force ARP mode"
  echo -e "  ${CYAN}-l, --list-interfaces${RESET}     List available network interfaces"
  echo -e "  ${CYAN}-h, --help${RESET}                Show this help"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo -e "  $0 ${YELLOW}192.168.1.0/24${RESET}"
  echo -e "  $0 ${YELLOW}192.168.1.1-50${RESET} -H"
  echo -e "  $0 ${YELLOW}192.168.1.1,192.168.1.254${RESET} -t 200"
  echo -e "  $0 ${YELLOW}10.0.0.0/8${RESET} -t 1000 -j 200 -o results.csv"
  echo -e "  $0 ${YELLOW}192.168.1.0/24${RESET} -e 192.168.1.1-10 -e 192.168.1.254"
  echo -e "  $0 ${YELLOW}8.8.8.8${RESET} -t 1500 -r 3 --icmp"
}

while [[ $# -gt 0 ]]; do
  case $1 in
  -t | --timeout)
    TIMEOUT=$2
    shift 2
    ;;
  -H | --no-hostname)
    HOSTNAME=false
    shift
    ;;
  -i | --interface)
    INTERFACE=$2
    shift 2
    ;;
  -j | --max-jobs)
    MAX_JOBS=$2
    shift 2
    ;;
  -r | --retry)
    RETRY=$2
    shift 2
    ;;
  -o | --output)
    OUTPUT=$2
    shift 2
    ;;
  -e | --exclude)
    EXCLUDE="$EXCLUDE,$2"
    shift 2
    ;;
  --no-color)
    NOCOLOR=true
    shift
    ;;
  --no-progress)
    NOPROGRESS=true
    shift
    ;;
  --icmp)
    MODE="ICMP"
    FORCED=true
    shift
    ;;
  --arp)
    MODE="ARP"
    FORCED=true
    shift
    ;;
  -h | --help)
    help
    exit 0
    ;;
  -l | --list-interfaces)
    ip -o link show | awk -F ': ' '{print $2}' | grep -v '^lo$'
    exit 0
    ;;
  -*)
    echo -e "${RED}Unknown flag:${RESET} $1"
    exit 1
    ;;
  *)
    TARGET=$1
    shift
    ;;
  esac
done

EXCLUDE="${EXCLUDE#,}"
if $NOCOLOR; then
  RED="" GREEN="" YELLOW="" BLUE="" CYAN="" BOLD="" RESET=""
fi

[[ -z "$TARGET" ]] && help && exit 1

if [[ "$TARGET" =~ $EXCL_CIDR ]]; then
  TARGET_TYPE="CIDR"

  IFS="/" read -r base_ip cidr <<<"$TARGET"
  IFS="." read -r bi1 bi2 bi3 bi4 <<<"$base_ip"

  MASK=$(cidr2mask $cidr)
  IFS="." read -r m1 m2 m3 m4 <<<"$MASK"
  mask_int=$(ip_to_int $m1 $m2 $m3 $m4)
  network=$(($(ip_to_int $bi1 $bi2 $bi3 $bi4) & mask_int))
  broadcast=$((network | (~mask_int & 0xFFFFFFFF)))
  mini=$((network + 1))
  maxi=$((broadcast - 1))
  [[ $cidr -eq 32 ]] && mini=$network && maxi=$network
  [[ $cidr -eq 31 ]] && mini=$network && maxi=$broadcast

elif [[ "$TARGET" =~ $RANGE ]]; then
  TARGET_TYPE="RANGE"

  IFS="." read -r o1 o2 o3 o4 <<<"$TARGET"

  parse_octet() {
    [[ "$1" == *"-"* ]] && echo "${1%-*} ${1#*-}" || echo "$1 $1"
  }

  read s1 e1 <<<$(parse_octet "$o1")
  read s2 e2 <<<$(parse_octet "$o2")
  read s3 e3 <<<$(parse_octet "$o3")
  read s4 e4 <<<$(parse_octet "$o4")

  for ((i1 = s1; i1 <= e1; i1++)); do
    for ((i2 = s2; i2 <= e2; i2++)); do
      for ((i3 = s3; i3 <= e3; i3++)); do
        for ((i4 = s4; i4 <= e4; i4++)); do
          TARGET_IPS+=("$i1.$i2.$i3.$i4")
        done
      done
    done
  done

elif [[ "$TARGET" =~ $SINGLE ]]; then
  TARGET_TYPE="SINGLE"

  IFS="." read -r bi1 bi2 bi3 bi4 <<<"$TARGET"

  mini=$(ip_to_int $bi1 $bi2 $bi3 $bi4)
  maxi=$mini

elif [[ "$TARGET" =~ $LIST ]]; then
  TARGET_TYPE="LIST"

  IFS="," read -ra ips <<<"$TARGET"
  for ip in "${ips[@]}"; do
    TARGET_IPS+=($ip)
  done

else
  echo -e "${RED}Error:${RESET} Invalid target format. See --help"
  exit 1
fi

declare -A EXCLUDE_IPS

if [[ -n "$EXCLUDE" ]]; then
  IFS=',' read -ra EXCLUDES <<<"$EXCLUDE"

  for EX in "${EXCLUDES[@]}"; do

    if [[ "$EX" =~ $EXCL_CIDR ]]; then
      IFS="/" read -r ex_base ex_cidr <<<"$EX"
      IFS="." read -r e1 e2 e3 e4 <<<"$ex_base"

      ex_int=$(((e1 << 24) + (e2 << 16) + (e3 << 8) + e4))
      ex_mask=$(cidr2mask $ex_cidr)

      IFS="." read -r em1 em2 em3 em4 <<<"$ex_mask"
      ex_mask_int=$(((em1 << 24) + (em2 << 16) + (em3 << 8) + em4))

      ex_network=$((ex_int & ex_mask_int))
      ex_broadcast=$((ex_network | (~ex_mask_int & 0xFFFFFFFF)))

      for ((i = ex_network + 1; i < ex_broadcast; i++)); do
        EXCLUDE_IPS[$(int_to_ip $i)]=1
      done

    elif [[ "$EX" =~ $RANGE ]]; then
      IFS="." read -r o1 o2 o3 o4 <<<"$EX"

      parse_octet() {
        [[ "$1" == *"-"* ]] && echo "${1%-*} ${1#*-}" || echo "$1 $1"
      }

      read s1 e1 <<<$(parse_octet "$o1")
      read s2 e2 <<<$(parse_octet "$o2")
      read s3 e3 <<<$(parse_octet "$o3")
      read s4 e4 <<<$(parse_octet "$o4")

      for ((i1 = s1; i1 <= e1; i1++)); do
        for ((i2 = s2; i2 <= e2; i2++)); do
          for ((i3 = s3; i3 <= e3; i3++)); do
            for ((i4 = s4; i4 <= e4; i4++)); do
              EXCLUDE_IPS["$i1.$i2.$i3.$i4"]=1
            done
          done
        done
      done

    elif [[ "$EX" =~ $LIST ]]; then
      IFS="," read -ra ips <<<"$EX"
      for ip in "${ips[@]}"; do
        EXCLUDE_IPS[$ip]=1
      done

    elif [[ "$EX" =~ $SINGLE ]]; then
      EXCLUDE_IPS[$EX]=1

    else
      echo -e "${RED}Error:${RESET} Invalid exclude format: $EX"
      exit 1
    fi

  done
fi
if [[ ${#TARGET_IPS[@]} -gt 0 ]]; then
  total=0
  for ip in "${TARGET_IPS[@]}"; do
    [[ -z "${EXCLUDE_IPS[$ip]}" ]] && ((total++))
  done
else
  total=0
  for ((ip_int = mini; ip_int <= maxi; ip_int++)); do
    IP=$(int_to_ip "$ip_int")
    [[ -z "${EXCLUDE_IPS[$IP]}" ]] && ((total++))
  done
fi

timestart=$(date +%s)
timeend=0

echo -e "${BOLD}Scanning${RESET} $(
  [[ "$TARGET_TYPE" == "SINGLE" ]] &&
    echo "$TARGET" ||
    [[ "$TARGET_TYPE" =~ ^(LIST|RANGE)$ ]] &&
    echo -e "${YELLOW}$total IPs${RESET} ${DIM}($(
      printf "%s " "${TARGET_IPS[@]:0:5}"
      [[ ${#TARGET_IPS[@]} -gt 5 ]] && echo "..."
    ))${RESET}" || echo "${CYAN}$(int_to_ip $mini) → $(int_to_ip $maxi)${RESET} [$total IPs]"
) using mode: ${YELLOW}$([[ "$FORCED" == "true" ]] && echo "Forced $MODE" || echo "Auto (ARP local / ICMP remote)")${RESET}"

[[ -n "$INTERFACE" ]] && echo -e "Interface: ${CYAN}$INTERFACE${RESET} ($(cat /sys/class/net/$INTERFACE/operstate 2>/dev/null || echo unknown))"
[[ -n "$EXCLUDE" ]] && echo -e "Excluding: ${YELLOW}$EXCLUDE${RESET}"

print_progress() {
  while true; do
    done=$(wc -l <"$DONE_FILE")

    [[ $total -eq 0 ]] && total=1

    percent=$(($done * 100 / total))
    filled=$((percent / 2))
    empty=$((50 - filled))
    bar=$(printf "%${filled}s" | tr ' ' '#')
    space=$(printf "%${empty}s")
    timeend=$(date +%s)
    speed=$((done / (timeend - timestart + 1)))
    left=$(((total - done) / (speed + 1)))
    echo -ne "\r\033[K${BOLD}[${GREEN}${bar}${RESET}${BOLD}${space}]${RESET} ${CYAN}$percent%${RESET} (${done}/${total}) ${YELLOW}${speed} IPs/s${RESET} - $((timeend - timestart))s - ≈${left}s left"
    [[ $done -ge $total ]] && break
    sleep 0.3
  done
}

if ! $NOPROGRESS; then
  print_progress &
  PROGRESS_PID=$!
fi

scan_ip() {
  local IP=$1
  [[ -n "${EXCLUDE_IPS[$IP]}" ]] && { echo 1 >>"$DONE_FILE" && return; }

  read -u 3

  {
    alive=false

    CURRENT_MODE="$MODE"

    if [[ "$FORCED" == "false" ]]; then

      ip_int=$(ip_to_int $(echo "$IP" | tr '.' ' '))
      if is_local_ip "$ip_int"; then
        CURRENT_MODE="ARP"
      else
        CURRENT_MODE="ICMP"
      fi
    fi

    latency=""
    MAC=""

    if [[ "$CURRENT_MODE" == "ICMP" ]]; then

      for ((i = 0; i < RETRY; i++)); do
        if result=$(fping -c 1 -t $TIMEOUT ${INTERFACE:+-I $INTERFACE} "$IP" 2>&1); then
          alive=true
          latency=$(echo "$result" | grep -oE '[0-9.]+ ms' | head -n1 | awk '{print $1}')
          break
        fi
      done

    elif [[ "$CURRENT_MODE" == "ARP" ]]; then

      for ((i = 0; i < RETRY; i++)); do
        result=$(arping -c 1 -w $(awk "BEGIN {printf \"%.2f\", $TIMEOUT/1000}") ${INTERFACE:+-I $INTERFACE} "$IP" 2>/dev/null)

        if echo "$result" | grep -q "bytes from"; then
          alive=true
          latency=$(echo "$result" | awk -F'=' '/rtt/ {split($2,a,"/"); print a[2]}')
          MAC=$(echo "$result" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1)
          break
        fi
      done

    fi
    if $alive; then
      hostname=""
      if $HOSTNAME; then
        hostname=$(dig ${INTERFACE:+-b $INTERFACE} -x $IP +short +time=1 +tries=$RETRY)
        [[ -z "$hostname" ]] && hostname="Unknown"
      fi
      echo -ne "\r\033[K"
      echo -e "${GREEN}●${RESET} ${BOLD}$IP${RESET} is alive${hostname:+ - ${GREEN}$hostname${RESET}}${MAC:+ - ${CYAN}$MAC${RESET}}${latency:+ - ${BLUE}$latency ms${RESET}}"
      [[ -n "$OUTPUT" ]] && echo "$IP${hostname:+,$hostname}" >>"$OUTPUT"
      echo 1 >>"$ALIVE_FILE"
    fi

    echo 1 >>"$DONE_FILE"
    echo >&3
  } &
}

if [[ ${#TARGET_IPS[@]} -gt 0 ]]; then
  for IP in "${TARGET_IPS[@]}"; do
    scan_ip "$IP"
  done
else
  for ((ip_int = mini; ip_int <= maxi; ip_int++)); do
    IP=$(int_to_ip "$ip_int")

    scan_ip "$IP"
  done
fi
wait
timeend=$(date +%s)

echo -ne "\r\033[K"
if ! $NOPROGRESS; then
  kill $PROGRESS_PID 2>/dev/null
  wait $PROGRESS_PID 2>/dev/null
fi

FOUND=$(wc -l <"$ALIVE_FILE")
echo -e "\n${BOLD}Scan completed${RESET} in $(echo "$timeend - $timestart" | bc).$(printf "%03d" $((($(date +%N) / 1000000) % 1000)))s${RESET} - ${GREEN}${BOLD}$FOUND${RESET} IP(s) found!"
[[ -n "$OUTPUT" ]] && echo -e "Results saved to ${CYAN}$OUTPUT${RESET}"

exit 0
