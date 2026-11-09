# pimcore-security-patches

Security patches for `pimcore/pimcore` 10.6.9 (Pimcore 10, PHP 8.1), applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

The 10.6 patch set is being populated: the table below is empty until a patch is added, verified and released.

## Install

Needs Composer 2 and PHP ≥ 8.1. Not on Packagist.

```bash
composer config repositories.pimcore-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer config allow-plugins.cweagans/composer-patches true
composer config allow-plugins.portadesign/pimcore-security-patches true
composer require portadesign/pimcore-security-patches:^10.6
bin/console cache:clear
```

Commit `composer.json`, `composer.lock` and `patches.lock.json`. Every `composer install`/`update` verifies the patches and re-applies them when needed. `pimcore/pimcore` must be 10.6.9 (`conflict` rejects older and 10.7+).

- Composer 2.10+ blocks `pimcore/pimcore` because of open advisories: put the `config.policy` part of `audit-ignore.json` into `composer.json` before `composer require`.

### Project on `cweagans/composer-patches` 1.x

Pimcore 10 projects often still use 1.x. This package requires 2.x, so Composer cannot resolve it next to a `^1` constraint.

1. Remove the 1.x pin: `composer remove cweagans/composer-patches`.
2. Keep your `extra.patches`: the compact `"description": "url"` format works in 2.x unchanged.
3. Delete `extra.enable-patching` and `extra.composer-exit-on-patch-failure`; they are 1.x only. A 1.x `extra.patches-file` becomes `extra.composer-patches.patches-file` (default `patches.json`).
4. Run the `composer require` above; it installs 2.x. Then `composer patches-relock && composer patches-repatch` and commit the new `patches.lock.json`.

## Versions

One branch and one tag series per Pimcore line; the version is the line: `^10.6` never installs an 11.5 patch set.

| Pimcore | Branch | Tags | Require |
| --- | --- | --- | --- |
| 10.6.x | `10.6` | `v10.6.<n>` | `^10.6` |
| 11.5.x | `11.5` | `v11.5.<n>` | `^11.5` |

## Patches

| CVE | Package | What changes |
| --- | --- | --- |
| none yet | | |

All patches are verified on 10.6.9. Each patch file starts with a header (CVE, advisory, verified versions, summary).

## Scanners

- Composer: copy `audit-ignore.json` into `composer.json` `config` (`audit.ignore`, and `policy.advisories.ignore-id` on 2.10+).
- Trivy: `vex.openvex.json` (OpenVEX, matches the `composer.lock` PURL with and without the `v` prefix) hides every CVE in the table above.

```yaml
# GitHub Actions
- uses: aquasecurity/trivy-action@0.28.0
  with: { scan-type: fs, scan-ref: ., scanners: vuln, severity: "HIGH,CRITICAL", exit-code: "1" }
  env:
    TRIVY_VEX: vendor/portadesign/pimcore-security-patches/vex.openvex.json
```

```yaml
# trivy.yaml for CLI runs
vulnerability:
  vex: [vendor/portadesign/pimcore-security-patches/vex.openvex.json]
```

Without `vendor/` in CI, copy `vex.openvex.json` into the project and point `TRIVY_VEX` there. Both lists hold only while the package is installed and its patches are applied.

## Maintain

- `./verify.sh [pimcore-tag]` (default `v10.6.9`): every patch applies to the pristine release tarball (needs `gh`); CI runs it on push and weekly.
- New patch: failing test in `tests/`, patch with header, entry in `extra.patches`, table row, `./verify.sh`.
- Status in `advisories.json`; `php bin/build-vex.php` regenerates `vex.openvex.json` and `audit-ignore.json`.
- Release: `./release.sh <line>.<n> [--dry-run]` on the line branch (`10.6.0` on `10.6`). Needs a clean tree, runs the unit tests and `verify.sh` for every tag in `.github/workflows/verify.yml`, pins patch URLs to the tag, syncs `sha256`, rebuilds the VEX, commits, tags and pushes branch and tag over SSH; fast-forwards `main` when this is the newest line.

## Tests

Exploit tests need a host project with a database (dist install omits `tests/`: clone the repo or `composer reinstall portadesign/pimcore-security-patches --prefer-source`). They create and remove their own fixtures.

```bash
T="-c vendor/portadesign/pimcore-security-patches/phpunit.xml.dist"; vendor/bin/phpunit $T
```

Plugin unit tests: `vendor/bin/phpunit -c phpunit.unit.xml.dist`.
