#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "install-agent.sh must run as root" >&2
  exit 1
fi
if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 /path/to/mysafe-agent https://control.example.com /path/to/bootstrap-token" >&2
  exit 2
fi

binary_path="$(readlink -f "$1")"
control_url="$2"
token_file="$(readlink -f "$3")"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unit_path="${script_dir}/../deploy/systemd/my-safe-agent.service"

if [[ ! -f "${binary_path}" || ! -x "${binary_path}" ]]; then
  echo "agent binary must exist and be executable" >&2
  exit 2
fi
if [[ ! "${control_url}" =~ ^https://[A-Za-z0-9._:-]+(/[^[:space:]\"\']*)?$ ]]; then
  echo "control URL must be HTTPS and contain no shell or environment-file metacharacters" >&2
  exit 2
fi
if [[ ! -f "${token_file}" ]]; then
  echo "bootstrap token file does not exist" >&2
  exit 2
fi
if [[ ! -f "${unit_path}" ]]; then
  echo "systemd unit is missing from the source tree" >&2
  exit 2
fi

if ! getent group my-safe >/dev/null; then
  groupadd --system my-safe
fi
if ! id my-safe >/dev/null 2>&1; then
  useradd --system --gid my-safe --home-dir /var/lib/my-safe --shell /usr/sbin/nologin my-safe
fi

install -o root -g root -m 0755 "${binary_path}" /usr/local/bin/mysafe-agent
install -d -o root -g my-safe -m 0750 /etc/my-safe
install -d -o my-safe -g my-safe -m 0700 /var/lib/my-safe
printf 'MYSAFE_CONTROL_URL=%s\nMYSAFE_STATE_DIR=/var/lib/my-safe\n' "${control_url}" > /etc/my-safe/agent.env
chown root:my-safe /etc/my-safe/agent.env
chmod 0640 /etc/my-safe/agent.env

bootstrap_token="$(tr -d '\r\n' < "${token_file}")"
if [[ "${#bootstrap_token}" -lt 16 ]]; then
  echo "bootstrap token must contain at least 16 bytes" >&2
  exit 2
fi
runuser -u my-safe -- env \
  MYSAFE_CONTROL_URL="${control_url}" \
  MYSAFE_STATE_DIR=/var/lib/my-safe \
  MYSAFE_BOOTSTRAP_TOKEN="${bootstrap_token}" \
  /usr/local/bin/mysafe-agent --once
unset bootstrap_token

install -o root -g root -m 0644 "${unit_path}" /etc/systemd/system/my-safe-agent.service
systemctl daemon-reload
systemctl enable --now my-safe-agent.service
echo "My Safe Agent registered and started. Remove the consumed bootstrap token file now."
