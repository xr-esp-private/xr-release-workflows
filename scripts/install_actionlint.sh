#!/bin/sh
set -eu

version=1.7.12
archive=actionlint_${version}_linux_amd64.tar.gz
expected=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
destination=${1:?usage: install_actionlint.sh DESTINATION_DIRECTORY}

mkdir -p "$destination"
curl -fsSLo "$destination/$archive" \
  "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}"
actual=$(sha256sum "$destination/$archive" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  echo "actionlint archive checksum mismatch" >&2
  exit 2
fi
tar -xzf "$destination/$archive" -C "$destination" actionlint
"$destination/actionlint" -version
