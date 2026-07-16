#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:?VERSION is required}"
output_dir="${OUTPUT_DIR:-${root_dir}/dist}"
deb_version="${version#v}"

if [[ ! "${deb_version}" =~ ^[0-9]+.[0-9]+.[0-9]+(-[0-9A-Za-z.+~]+)?$ ]]; then
  echo "VERSION is not a supported Debian package version: ${version}" >&2
  exit 2
fi
if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb is required" >&2
  exit 1
fi

package_component() {
  local component="$1"
  local arch="$2"
  local package_name="my-safe-${component}"
  local binary="${output_dir}/mysafe-${component}-linux-${arch}"
  local stage
  stage="$(mktemp -d -t mysafe-deb.XXXXXXXX)"
  trap 'rm -rf -- "${stage}"' RETURN

  test -f "${binary}"
  install -d -m 0755 "${stage}/DEBIAN" "${stage}/usr/local/bin"
  install -m 0755 "${binary}" "${stage}/usr/local/bin/mysafe-${component}"

  local description="My Safe ${component} component"
  local depends=""
  case "${component}" in
    agent)
      install -d -m 0755 "${stage}/etc/systemd/system" "${stage}/etc/my-safe"
      install -m 0644 "${root_dir}/deploy/systemd/my-safe-agent.service" "${stage}/etc/systemd/system/my-safe-agent.service"
      install -m 0644 "${root_dir}/deploy/agent.env.example" "${stage}/etc/my-safe/agent.env.example"
      install -m 0644 "${root_dir}/deploy/release-public-key.pem" "${stage}/etc/my-safe/release-public-key.pem"
      ;;
    gateway)
      depends="Depends: my-safe-agent (= ${deb_version})"
      install -d -m 0755 "${stage}/etc/systemd/system" "${stage}/etc/my-safe"
      install -m 0644 "${root_dir}/deploy/systemd/my-safe-gateway.service" "${stage}/etc/systemd/system/my-safe-gateway.service"
      install -m 0644 "${root_dir}/deploy/gateway.env.example" "${stage}/etc/my-safe/gateway.env.example"
      ;;
    control)
      install -d -m 0755 "${stage}/etc/systemd/system" "${stage}/etc/my-safe"
      install -m 0644 "${root_dir}/deploy/systemd/my-safe-control.service" "${stage}/etc/systemd/system/my-safe-control.service"
      install -m 0644 "${root_dir}/deploy/control.env.example" "${stage}/etc/my-safe/control.env.example"
      ;;
    installer) ;;
    *) echo "unsupported component: ${component}" >&2; return 2 ;;
  esac

  {
    printf 'Package: %s\n' "${package_name}"
    printf 'Version: %s\n' "${deb_version}"
    printf 'Section: admin\nPriority: optional\nArchitecture: %s\n' "${arch}"
    [[ -z "${depends}" ]] || printf '%s\n' "${depends}"
    printf 'Maintainer: My Safe <noreply@example.invalid>\n'
    printf 'Description: %s\n' "${description}"
  } > "${stage}/DEBIAN/control"

  if [[ "${component}" != "installer" ]]; then
    {
      printf '#!/bin/sh\nset -e\n'
      case "${component}" in
        agent)
          printf 'getent group my-safe >/dev/null || groupadd --system my-safe\n'
          printf 'id my-safe >/dev/null 2>&1 || useradd --system --gid my-safe --home-dir /var/lib/my-safe --shell /usr/sbin/nologin my-safe\n'
          printf 'install -d -o my-safe -g my-safe -m 0700 /var/lib/my-safe\n'
          printf 'install -d -o root -g my-safe -m 0750 /etc/my-safe\n'
          ;;
        gateway)
          printf 'getent group my-safe-gateway >/dev/null || groupadd --system my-safe-gateway\n'
          printf 'id my-safe-gateway >/dev/null 2>&1 || useradd --system --gid my-safe-gateway --home-dir /nonexistent --shell /usr/sbin/nologin my-safe-gateway\n'
          ;;
        control)
          printf 'getent group my-safe-control >/dev/null || groupadd --system my-safe-control\n'
          printf 'id my-safe-control >/dev/null 2>&1 || useradd --system --gid my-safe-control --home-dir /var/lib/my-safe-control --shell /usr/sbin/nologin my-safe-control\n'
          ;;
      esac
      printf 'systemctl daemon-reload >/dev/null 2>&1 || true\nexit 0\n'
    } > "${stage}/DEBIAN/postinst"
    chmod 0755 "${stage}/DEBIAN/postinst"
  fi

  dpkg-deb --build --root-owner-group "${stage}" "${output_dir}/mysafe-${component}-linux-${arch}.deb" >/dev/null
  rm -rf -- "${stage}"
  trap - RETURN
}

for arch in amd64 arm64; do
  for component in agent control gateway installer; do
    package_component "${component}" "${arch}"
  done
done

echo "Debian packages written to ${output_dir}"
