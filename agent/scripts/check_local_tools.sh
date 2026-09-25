#!/usr/bin/env bash
# check_local_tools.sh — host-tool preflight for REDTEAM_RUNTIME_MODE=local
# (bare-metal Kali Linux). Verifies the pentest toolchain is present on PATH and
# prints exact install commands. With --install it also installs the missing
# packages via apt-get / go install / pipx.
#
# Usage:
#   ./scripts/check_local_tools.sh            # report only (exit 1 if missing)
#   ./scripts/check_local_tools.sh --install  # install missing tools
#   ./scripts/check_local_tools.sh --quiet    # exit code only
set -uo pipefail

INSTALL=0
QUIET=0
for arg in "$@"; do
    case "$arg" in
        --install) INSTALL=1 ;;
        --quiet|-q) QUIET=1 ;;
        -h|--help)
            cat <<'EOF'
check_local_tools.sh — host-tool preflight for REDTEAM_RUNTIME_MODE=local
(bare-metal Kali Linux). Verifies the pentest toolchain is present on PATH and
prints exact install commands. With --install it also installs the missing
packages via apt-get / go install / pipx.

Usage:
  ./scripts/check_local_tools.sh            # report only (exit 1 if missing)
  ./scripts/check_local_tools.sh --install  # install missing tools
  ./scripts/check_local_tools.sh --quiet    # exit code only
EOF
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
say() { [ "$QUIET" = "1" ] || printf '%b\n' "$*"; }

# binary|apt-package|go-module|pipx-package
TOOLS=(
    "nmap|nmap||"
    "nikto|nikto||"
    "whatweb|whatweb||"
    "gobuster|gobuster||"
    "ffuf|ffuf||"
    "dirb|dirb||"
    "wfuzz|wfuzz||"
    "sqlmap|sqlmap||"
    "hydra|hydra||"
    "hashcat|hashcat||"
    "john|john||"
    "smbclient|smbclient||"
    "ldapsearch|ldap-utils||"
    "dnsenum|dnsenum||"
    "enum4linux|enum4linux||"
    "socat|socat||"
    "sslscan|sslscan||"
    "testssl|testssl.sh||"
    "impacket-psexec|python3-impacket||"
    "docker|docker.io||"
    "kubectl|kubernetes-client||"
    "nc|netcat-traditional||"
    "wget|wget||"
    "curl|curl||"
    "nuclei|nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|"
    "subfinder|subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|"
    "katana|katana|github.com/projectdiscovery/katana/cmd/katana@latest|"
    "arjun|||arjun"
    "mitmdump|mitmproxy||"
    "chromium|chromium||"
    "chromedriver|chromium-driver||"
    "msfrpcd|metasploit-framework||"
    "rg|ripgrep||"
    "jq|jq||"
    "sqlite3|sqlite3||"
    "python3|python3||"
    "openssl|openssl||"
    "dig|dnsutils||"
    "whois|whois||"
    "git|git||"
    "tcpdump|tcpdump||"
    "tshark|tshark||"
    "xxd|xxd||"
    "sipp|sip-tester||"
    "searchsploit|exploitdb||"
    "unzip|unzip||"
    "tar|tar||"
    "ssh|openssh-client||"
    "ss|iproute2||"
)

# path|apt-package|description
PATHS=(
    "/usr/share/wordlists|wordlists|wordlists directory (rockyou)"
    "/usr/share/seclists|seclists|SecLists discovery/fuzzing wordlists"
)

missing_bins=()
missing_paths=()
apt_pkgs=()
go_mods=()
pipx_pkgs=()
ok_count=0

command -v apt-get >/dev/null 2>&1 || HAVE_APT=0
HAVE_APT=${HAVE_APT:-1}
command -v go >/dev/null 2>&1 && HAVE_GO=1 || HAVE_GO=0
command -v pipx >/dev/null 2>&1 && HAVE_PIPX=1 || HAVE_PIPX=0

say "${BLUE}[local-tools] Checking host pentest toolchain...${NC}"
for entry in "${TOOLS[@]}"; do
    IFS='|' read -r bin apt mod pipx <<<"$entry"
    if command -v "$bin" >/dev/null 2>&1; then
        ok_count=$((ok_count + 1))
        say "  ${GREEN}[OK]${NC} $bin ($(command -v "$bin"))"
        continue
    fi
    missing_bins+=("$bin")
    say "  ${RED}[MISSING]${NC} $bin"
    [ -n "$apt" ] && apt_pkgs+=("$apt")
    [ -n "$mod" ] && go_mods+=("$mod")
    [ -n "$pipx" ] && pipx_pkgs+=("$pipx")
done

for entry in "${PATHS[@]}"; do
    IFS='|' read -r path apt desc <<<"$entry"
    if [ -e "$path" ]; then
        ok_count=$((ok_count + 1))
        say "  ${GREEN}[OK]${NC} $desc ($path)"
    else
        missing_paths+=("$path")
        say "  ${RED}[MISSING]${NC} $desc ($path)"
        [ -n "$apt" ] && apt_pkgs+=("$apt")
    fi
done

# De-duplicate apt packages while preserving order.
if [ ${#apt_pkgs[@]} -gt 0 ]; then
    mapfile -t apt_pkgs < <(printf '%s\n' "${apt_pkgs[@]}" | awk '!seen[$0]++')
fi

if [ ${#missing_bins[@]} -eq 0 ] && [ ${#missing_paths[@]} -eq 0 ]; then
    say ""
    say "${GREEN}[local-tools] All ${ok_count} host tools present.${NC}"
    exit 0
fi

say ""
say "${YELLOW}[local-tools] ${#missing_bins[@]} missing tool(s), ${#missing_paths[@]} missing path(s).${NC}"

if [ "$INSTALL" = "1" ]; then
    say ""
    say "${BLUE}[local-tools] Installing missing packages (--install)...${NC}"
    SUDO=""
    [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

    if [ ${#apt_pkgs[@]} -gt 0 ]; then
        if [ "$HAVE_APT" = "1" ]; then
            say "  apt-get install -y ${apt_pkgs[*]}"
            $SUDO apt-get update -y || say "  ${YELLOW}[WARN] apt-get update failed; continuing${NC}"
            $SUDO apt-get install -y "${apt_pkgs[@]}" || say "  ${YELLOW}[WARN] some apt packages failed${NC}"
        else
            say "  ${YELLOW}[WARN] apt-get not available; install manually: ${apt_pkgs[*]}${NC}"
        fi
    fi

    if [ ${#go_mods[@]} -gt 0 ]; then
        if [ "$HAVE_GO" = "1" ]; then
            for mod in "${go_mods[@]}"; do
                say "  go install $mod"
                go install "$mod" || say "  ${YELLOW}[WARN] go install failed for $mod${NC}"
            done
        else
            say "  ${YELLOW}[WARN] go not installed; install golang then: go install ${go_mods[*]}${NC}"
        fi
    fi

    if [ ${#pipx_pkgs[@]} -gt 0 ]; then
        if [ "$HAVE_PIPX" = "1" ]; then
            for pkg in "${pipx_pkgs[@]}"; do
                say "  pipx install $pkg"
                pipx install "$pkg" || say "  ${YELLOW}[WARN] pipx install failed for $pkg${NC}"
            done
        else
            say "  ${YELLOW}[WARN] pipx not installed; install python3-pip/pipx then: pipx install ${pipx_pkgs[*]}${NC}"
        fi
    fi

    say ""
    say "${BLUE}[local-tools] Re-checking...${NC}"
    still_missing=0
    for bin in "${missing_bins[@]}"; do
        command -v "$bin" >/dev/null 2>&1 || { still_missing=$((still_missing + 1)); say "  ${RED}[STILL MISSING]${NC} $bin"; }
    done
    for path in "${missing_paths[@]}"; do
        [ -e "$path" ] || { still_missing=$((still_missing + 1)); say "  ${RED}[STILL MISSING]${NC} $path"; }
    done
    if [ "$still_missing" -eq 0 ]; then
        say "${GREEN}[local-tools] All tools installed.${NC}"
        exit 0
    fi
    say "${YELLOW}[local-tools] $still_missing item(s) still missing (see warnings above).${NC}"
    exit 1
fi

say ""
say "Install hints:"
[ ${#apt_pkgs[@]} -gt 0 ] && say "  apt:  sudo apt-get install -y ${apt_pkgs[*]}"
[ ${#go_mods[@]} -gt 0 ] && say "  go:   go install ${go_mods[*]}"
[ ${#pipx_pkgs[@]} -gt 0 ] && say "  pipx: pipx install ${pipx_pkgs[*]}"
say "  or re-run this installer with: ./install.sh kali <dir> --install"
exit 1
