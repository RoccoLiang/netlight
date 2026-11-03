#!/usr/bin/env bash
# 交叉編譯四個平台的單一執行檔到 dist/
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}" # 畫面已加 v，避免出現 vv1.0.0
rm -rf dist
mkdir -p dist
for target in darwin/arm64 darwin/amd64 windows/amd64 linux/amd64; do
	os="${target%/*}"; arch="${target#*/}"
	out="dist/netlight-${os}-${arch}"
	[ "$os" = windows ] && out="${out}.exe"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$out" .
	echo "$out"
done
cp netlight.example.json dist/

# Windows zip：資料夾內含 exe、example.json、中文使用說明（ASCII 檔名）
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
mkdir -p "${tmpdir}/netlight-windows-amd64"
cp dist/netlight-windows-amd64.exe netlight.example.json "${tmpdir}/netlight-windows-amd64/"
cp packaging/windows/README.txt "${tmpdir}/netlight-windows-amd64/README.txt"
cp LICENSE THIRD_PARTY_NOTICES.txt "${tmpdir}/netlight-windows-amd64/"
(cd "$tmpdir" && zip -qr -X "${OLDPWD}/dist/netlight-windows-amd64.zip" netlight-windows-amd64)
echo dist/netlight-windows-amd64.zip

# macOS／Linux tar.gz：資料夾內含執行檔（保留可執行權限）、example.json、中文使用說明
for target in darwin-arm64 darwin-amd64 linux-amd64; do
	dir="${tmpdir}/netlight-${target}"
	mkdir -p "$dir"
	cp "dist/netlight-${target}" netlight.example.json "$dir/"
	case "$target" in
		darwin-*) readme=macos ;;
		linux-*) readme=linux ;;
	esac
	cp "packaging/${readme}/README.txt" "${dir}/README.txt"
	cp LICENSE THIRD_PARTY_NOTICES.txt "$dir/"
	chmod 755 "${dir}/netlight-${target}"
	COPYFILE_DISABLE=1 tar --no-xattrs --no-acls -czf "dist/netlight-${target}.tar.gz" -C "$tmpdir" "netlight-${target}"
	echo "dist/netlight-${target}.tar.gz"
done

rm -rf "$tmpdir"
trap - EXIT

cp LICENSE THIRD_PARTY_NOTICES.txt dist/

# SHA256SUMS：所有發佈檔的校驗和（原子寫入）
(cd dist && shasum -a 256 netlight-* netlight.example.json > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS)
echo dist/SHA256SUMS
