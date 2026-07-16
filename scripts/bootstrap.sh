#!/usr/bin/env bash
set -euo pipefail

version=""
control_url=""
token_file=""
gateway="auto"
upstream=""
gateway_port="0"
base_url=""
allow_experimental="false"
dry_run="false"

usage() {
  cat <<'USAGE'
Usage: bootstrap.sh --version vX.Y.Z --control-url https://control.example.com \
  --bootstrap-token-file /root/my-safe-token [options]

Options:
  --gateway auto|enabled|disabled
  --upstream URL
  --gateway-port PORT
  --allow-experimental
  --dry-run
  --base-url URL        Override the GitHub Release download base (testing/mirror)
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --control-url) control_url="${2:-}"; shift 2 ;;
    --bootstrap-token-file) token_file="${2:-}"; shift 2 ;;
    --gateway) gateway="${2:-}"; shift 2 ;;
    --upstream) upstream="${2:-}"; shift 2 ;;
    --gateway-port) gateway_port="${2:-}"; shift 2 ;;
    --allow-experimental) allow_experimental="true"; shift ;;
    --dry-run) dry_run="true"; shift ;;
    --base-url) base_url="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "bootstrap.sh must run as root" >&2
  exit 1
fi
if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "--version must be SemVer such as v0.2.0" >&2
  exit 2
fi
if [[ -z "${control_url}" ]]; then
  echo "--control-url is required" >&2
  exit 2
fi
if [[ "${dry_run}" != "true" && ! -f "${token_file}" ]]; then
  echo "--bootstrap-token-file must name a readable file" >&2
  exit 2
fi
case "${gateway}" in auto|enabled|disabled) ;; *) echo "--gateway must be auto, enabled, or disabled" >&2; exit 2 ;; esac
if [[ ! "${gateway_port}" =~ ^[0-9]+$ ]] || (( gateway_port < 0 || gateway_port > 65535 )); then
  echo "--gateway-port must be between 0 and 65535" >&2
  exit 2
fi

case "$(uname -m)" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

for command in curl openssl base64 sha256sum awk mktemp; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "required command is missing: ${command}" >&2
    exit 1
  fi
done

if [[ -z "${base_url}" ]]; then
  base_url="https://github.com/HCRXchenghong/my-safe/releases/download/${version}"
fi
if [[ ! "${base_url}" =~ ^https://[^[:space:]\"\']+$ && ! "${base_url}" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?/[^[:space:]\"\']*$ ]]; then
  echo "release base URL must use HTTPS (or loopback HTTP for testing)" >&2
  exit 2
fi

temporary="$(mktemp -d -t my-safe-bootstrap.XXXXXXXX)"
cleanup() {
  rm -rf -- "${temporary}"
}
trap cleanup EXIT INT TERM

download() {
  local name="$1"
  local destination="$2"
  local flags=(-fsSL --retry 4 --retry-delay 2 --retry-all-errors --connect-timeout 15 --max-time 300)
  if [[ "${base_url}" == https://* ]]; then
    flags+=(--proto '=https' --tlsv1.2)
  fi
  curl "${flags[@]}" "${base_url}/${name}" -o "${destination}"
}

download release-manifest.json "${temporary}/release-manifest.json"
download release-manifest.sig "${temporary}/release-manifest.sig"

cat > "${temporary}/release-public-key.pem" <<'PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxw6pvSJaPf5J685XXwsiZn0Kg+0fIfdDWz48zl8S15s=
-----END PUBLIC KEY-----
PUBLIC_KEY

base64 --decode "${temporary}/release-manifest.sig" > "${temporary}/release-manifest.sig.bin"
if ! openssl pkeyutl -verify -pubin \
  -inkey "${temporary}/release-public-key.pem" \
  -rawin -in "${temporary}/release-manifest.json" \
  -sigfile "${temporary}/release-manifest.sig.bin" >/dev/null; then
  echo "release manifest signature verification failed" >&2
  exit 1
fi

manifest_sha() {
  local target="$1"
  awk -v target="${target}" '
    $0 ~ "\\\"name\\\": \\\"" target "\\\"" { found=1; next }
    found && /"sha256":/ {
      value=$0
      sub(/^.*"sha256": *"/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
    found && /}/ { exit 3 }
  ' "${temporary}/release-manifest.json"
}

for component in installer agent gateway; do
  name="mysafe-${component}-linux-${arch}"
  expected="$(manifest_sha "${name}")"
  if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "signed manifest does not contain a valid hash for ${name}" >&2
    exit 1
  fi
  download "${name}" "${temporary}/${name}"
  printf '%s  %s\n' "${expected}" "${temporary}/${name}" | sha256sum --check --status
done

chmod 0755 "${temporary}/mysafe-installer-linux-${arch}"
arguments=(
  install
  --bundle "${temporary}"
  --manifest "${temporary}/release-manifest.json"
  --signature "${temporary}/release-manifest.sig"
  --expected-version "${version}"
  --control-url "${control_url}"
  --gateway "${gateway}"
  --gateway-port "${gateway_port}"
)
if [[ -n "${upstream}" ]]; then
  arguments+=(--upstream "${upstream}")
fi
if [[ "${dry_run}" == "true" ]]; then
  arguments+=(--dry-run)
else
  arguments+=(--bootstrap-token-file "${token_file}")
fi
if [[ "${allow_experimental}" == "true" ]]; then
  arguments+=(--allow-experimental)
fi

"${temporary}/mysafe-installer-linux-${arch}" "${arguments[@]}"
