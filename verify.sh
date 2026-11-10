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
probe_minipaint() {
  local probe="$root/tests/js/minipaint-jquery-probe.cjs" bundle="$1/bundles/AdminBundle/Resources/public/js/lib/minipaint/dist/bundle.js"
  [ -f "$probe" ] && [ -f "$bundle" ] || return 0
  if ! command -v node > /dev/null 2>&1; then
    echo "SKIP minipaint jQuery probe (node not installed)"
    return 0
  fi
  if node "$probe" "$bundle" --check; then
    echo "OK   minipaint jQuery probe"
  else
    echo "FAIL minipaint jQuery probe"
    return 1
  fi
}
check() {
  local fail=0 package=$2 names name
  names=$(ordered_patches "$package")
  if [ -z "$names" ]; then
    echo "no patches listed for $package ($3)"
    return 0
  fi
  echo "-- sequential apply ($3)"
  (cd "$1" && git init -q) || fail=1
  for name in $names; do
    p="$root/patches/$name"
    if (cd "$1" && git apply --check "$p" && patch -p1 --dry-run -s < "$p" > /dev/null && git apply "$p"); then
      echo "OK   $name"
    else
      echo "FAIL $name"; fail=1
    fi
  done
  probe_minipaint "$1" || fail=1
  return $fail
}
fetch pimcore/pimcore "$pimcore_tag" "$work/pimcore"
status=0
check "$work/pimcore" pimcore/pimcore "pimcore/pimcore $pimcore_tag" || status=1
exit $status
