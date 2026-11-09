#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
pimcore_tag=${1:-v10.6.9}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() { mkdir -p "$3" && gh api "repos/$1/tarball/$2" | tar xz --strip-components=1 -C "$3"; }
ordered_patches() {
  php -r '
    $extra = json_decode(file_get_contents($argv[1] . "/composer.json"), true)["extra"]["patches"][$argv[2]] ?? [];
    foreach ($extra as $patch) { echo basename($patch["url"]), "\n"; }
  ' "$root" "$1"
}
check() {
  local fail=0 package=$2 names name
  names=$(ordered_patches "$package")
  if [ -z "$names" ]; then
    echo "no patches listed for $package ($3)"
    return 0
  fi
  for name in $names; do
    p="$root/patches/$name"
    if (cd "$1" && git apply --check "$p" && patch -p1 --dry-run -s < "$p" > /dev/null); then
      echo "OK   $(basename "$p")"
    else
      echo "FAIL $(basename "$p")"; fail=1
    fi
  done
  echo "-- sequential apply ($3)"
  (cd "$1" && git init -q && failed=0 && for name in $names; do git apply "$root/patches/$name" || { echo "FAIL sequential $name"; failed=1; }; done; exit $failed) || fail=1
  return $fail
}
fetch pimcore/pimcore "$pimcore_tag" "$work/pimcore"
status=0
check "$work/pimcore" pimcore/pimcore "pimcore/pimcore $pimcore_tag" || status=1
exit $status
