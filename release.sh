#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: ./release.sh <line>.<n> [--dry-run]   (e.g. 11.5.0 on branch 11.5)" >&2
  exit 2
}
die() {
  echo "release.sh: $*" >&2
  exit 1
}
step() {
  echo "==> $*"
}
run() {
  if [ "$dry_run" = 1 ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}
matrix() {
  sed -n -E "s/^[[:space:]]*$1:[[:space:]]*\[(.*)\][[:space:]]*$/\1/p" .github/workflows/verify.yml | tr -d ' ' | tr ',' ' '
}

dry_run=0
version=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry_run=1 ;;
    -*) usage ;;
    *) [ -z "$version" ] || usage; version=$arg ;;
  esac
done
[ -n "$version" ] || usage

cd "$(dirname "$0")"

step "branch and version"
branch=$(git symbolic-ref --quiet --short HEAD) || die "detached HEAD"
[[ "$branch" =~ ^[0-9]+\.[0-9]+$ ]] || die "branch '$branch' is not a Pimcore line branch (<major>.<minor>)"
[[ "$version" =~ ^${branch//./\\.}\.[0-9]+$ ]] || die "version '$version' must match ${branch}.<n> on branch ${branch}"
tag="v${version}"
git rev-parse -q --verify "refs/tags/${tag}" > /dev/null && die "tag ${tag} already exists"
git remote get-url --push origin | grep -Eq '^(git@|ssh://)' || die "origin push URL is not SSH"

step "clean tree"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "working tree has uncommitted changes to tracked files"

step "unit tests"
vendor/bin/phpunit -c phpunit.unit.xml.dist

step "verify.sh for every combination in .github/workflows/verify.yml"
pimcore_tags=$(matrix pimcore)
admin_tags=$(matrix admin)
[ -n "$pimcore_tags" ] && [ -n "$admin_tags" ] || die "no pimcore/admin matrix found in .github/workflows/verify.yml"
for pimcore_tag in $pimcore_tags; do
  for admin_tag in $admin_tags; do
    echo "-- pimcore ${pimcore_tag} / admin-ui ${admin_tag}"
    ./verify.sh "$pimcore_tag" "$admin_tag" || die "verify.sh failed for ${pimcore_tag} / ${admin_tag}"
  done
done

step "patch files"
for f in patches/*.patch; do
  grep -q "^diff --git" "$f" || die "no diff in $f"
done

step "pin patch URLs to ${tag}, sync sha256"
if [ "$dry_run" = 1 ]; then
  echo "[dry-run] sed raw.githubusercontent.com/portadesign/pimcore-11-security-patches/v*/ -> ${tag}/ in composer.json"
  echo "[dry-run] php bin/sync-patch-hashes.php"
else
  sed -i.bak -E "s#(raw.githubusercontent.com/portadesign/pimcore-11-security-patches/)v[0-9]+\.[0-9]+\.[0-9]+/#\1${tag}/#" composer.json
  rm composer.json.bak
  php bin/sync-patch-hashes.php
fi

step "rebuild VEX and audit-ignore"
run php bin/build-vex.php --bump --tooling="${tag}"

step "commit and tag"
run git add composer.json vex.openvex.json audit-ignore.json
run git commit -qm "chore: release ${tag}"
run git tag "$tag"

push_refs=("$branch" "$tag")
newest=$(git for-each-ref --format='%(refname:short)' refs/heads refs/remotes/origin | sed 's#^origin/##' | grep -E '^[0-9]+\.[0-9]+$' | sort -V -u | tail -n 1)
if git rev-parse -q --verify refs/heads/main > /dev/null && [ "$branch" = "$newest" ] && git merge-base --is-ancestor main HEAD; then
  step "fast-forward main to ${branch}"
  run git branch -f main HEAD
  push_refs+=(main)
else
  step "main untouched (not an ancestor of HEAD, or ${branch} is not the newest line ${newest})"
fi

step "push over SSH: ${push_refs[*]}"
run git push --atomic -q origin "${push_refs[@]}"

if [ "$dry_run" = 1 ]; then
  echo "dry run finished: nothing committed, tagged or pushed"
else
  echo "released ${tag}"
fi
