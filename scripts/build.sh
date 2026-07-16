#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-dev}"
output_dir="${OUTPUT_DIR:-${root_dir}/dist}"

mkdir -p "${output_dir}"
cd "${root_dir}"

go test ./...
go vet ./...

for arch in amd64 arm64; do
  for command in mysafe-agent mysafe-control mysafe-gateway mysafe-installer; do
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build \
      -buildvcs=false \
      -trimpath \
      -ldflags "-s -w -X github.com/HCRXchenghong/my-safe/internal/agent.Version=${version}" \
      -o "${output_dir}/${command}-linux-${arch}" \
      "./cmd/${command}"
  done
done

if command -v dpkg-deb >/dev/null 2>&1; then
  VERSION="${version}" OUTPUT_DIR="${output_dir}" bash scripts/package-deb.sh
else
  echo "dpkg-deb unavailable; skipping optional Debian package build" >&2
fi

(cd "${output_dir}" && sha256sum mysafe-*-linux-* > SHA256SUMS)
echo "Artifacts written to ${output_dir}"
