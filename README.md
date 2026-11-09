# pimcore-security-patches

Security patches for `pimcore/pimcore` 10.6.9 (Pimcore 10, PHP 8.1), applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

## Install

Needs Composer 2 and PHP ≥ 8.1. Not on Packagist.

```bash
composer config repositories.pimcore-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer config allow-plugins.cweagans/composer-patches true
composer config allow-plugins.portadesign/pimcore-security-patches true
composer require portadesign/pimcore-security-patches:^10.6
bin/console cache:clear
```

Commit `composer.json`, `composer.lock` and `patches.lock.json`. Every `composer install`/`update` verifies the patches and re-applies them when needed. `pimcore/pimcore` must be 10.6.9 (`conflict` rejects older and 10.7+). `conflict` also rejects `phpoffice/phpspreadsheet <1.30.7` and `twig/twig <3.14.1`; if `composer require` reports one, run `composer update phpoffice/phpspreadsheet twig/twig` first.

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
| CVE-2026-23492 | pimcore | Admin search validates and quotes object brick names in the filter join |
| CVE-2023-47637 | pimcore | Multiselect grid filter quotes the value and escapes LIKE wildcards |
| CVE-2025-27617 | pimcore | Relation, image and hotspotimage grid filters quote value and column |
| CVE-2026-44741 | pimcore | Translation grid filters accept only known columns and quote them |
| CVE-2026-44739 | pimcore | Custom report keyword guard sees through whitespace and comments |
| CVE-2026-55416 | pimcore | Custom report fragments, identifiers and LIMIT are validated or cast |
| PD-2026-003 | pimcore | Select-type grid filters quote the value and escape LIKE wildcards |
| PD-2026-006 | pimcore | Note list filter accepts only notes columns and quotes them |
| PD-2026-007 | pimcore | Grid classification store sort accepts only existing fields and quotes the join alias |
| CVE-2026-55634 | pimcore | DataObject field names must match an identifier allowlist; field-name DDL is quoted |
| CVE-2026-55072 | pimcore | Class id and name are validated with anchored patterns before DDL and before any generated PHP; table names from the class id are quoted |
| CVE-2026-5394 | pimcore | Composite index keys and columns are validated and quoted |
| CVE-2026-55220 | pimcore | Hotspotimage, ImageGallery, Block, Video, Site and TmpStore unserialize only allowlisted classes (`pimcore.tmp_store.unserialize_allowed_classes`) |
| CVE-2026-45162 | pimcore | Remaining unserialize() paths take allowlists; element session data in tmp_store is HMAC-signed; the WebDAV delete-log allowlist is part of the CVE-2026-45260 patch |
| CVE-2026-23493 | pimcore | HTTP error log stores no cookies or server variables; run `UPDATE http_error_log SET cookies = 'a:0:{}', serverVars = 'a:0:{}';` once for old rows |
| CVE-2026-11407 | pimcore | Twig sandbox policy: blocked classes (user, token, session, request bags, CSRF handler, DAO, listings, DBAL, PDO, container, kernel, process, Twig, class/brick/field-collection/custom-layout definitions), blocked `pimcore_*` functions that read files, dump or instantiate classes, render templates, run editables or change render state (incl. `pimcore_minimize_scripts`, navigation, editables), no static, magic or `__call`-forwarded methods on models, hard-blocked mutators (`save*`, `delete*`, `set*`, ...), secret getters, request input readers (body, query, URI, credentials, client IP, session, accept headers), workflow transitions, translator, message catalogue and app state changes. Needs Twig >= 3.14.1. `objectTypes` arguments restricted to object/variant/folder; array thumbnail configs rejected in a sandbox. Config: `pimcore.templating_engine.twig.sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}` |
| PD-2026-002 (no CVE, hardening) | pimcore | Resent logged mails and the application log summary mail are sent without template rendering; the mail log stores the subject that was sent. The log summary mail and workflow notification mails keep a plain-text part |
| PD-2026-005 (no CVE, hardening) | pimcore | Default mail sender `no-reply@<host>`, links/files in mail bodies and the workflow notification deeplink use `general.domain` before the request host |
| CVE-2026-45260 | pimcore | WebDAV MOVE needs `create` on the destination, `publish` on the asset, `delete` when overwriting/restoring, `rename` for a rename; checked before the destination is deleted (existing folder destination needs `rename`, a taken cross-folder target is refused with 409); a failed save returns 500; the delete-log allowlist of CVE-2026-45162 (`Tree::move()`) is in the same patch |
| CVE-2026-45703 | pimcore | Word/XLIFF export return 403 for elements the user may not `view`; the export job list omits them |
| CVE-2026-45704 | pimcore | Custom report detail, data, chart, drill-down, CSV and newsletter report picker endpoints enforce the listing sharing rule; `reports_config` users and admins keep access; CSV exports are bound to the creating user |
| CVE-2026-23494 | pimcore | Static routes list needs `routes` |
| CVE-2026-23495 | pimcore | Predefined properties list needs `predefined_properties` |
| CVE-2024-24822 | pimcore | Tag add/delete/update need `tags_configuration`, element tags and assignment need `tags_assignment`, the tag tree needs one of `tags_configuration`, `tags_assignment`, `tags_search` |
| CVE-2024-41109 | pimcore | `/admin/index/statistics` needs `system_settings` |
| PD-2026-004 | pimcore | Export download 404s (word, XLIFF, report CSV) no longer contain filesystem paths; XLIFF export ids must match `^[a-z0-9]+$` (hardening, no public advisory) |
| GHSA-hq76-662x-7mw4 | pimcore | `conflict` `phpoffice/phpspreadsheet <1.30.7`: advisory fix is 1.29.1 (CVE-2024-45048), the floor is the first 1.x release without a published 1.x advisory and so also covers the 28 advisories fixed after 1.29.1 and the two fixed in 1.29.1 itself (CVE-2024-45293, CVE-2024-45046); run `composer update phpoffice/phpspreadsheet` once |
| GHSA-jmh9-6rjq-gjh9 | pimcore | image editor: `jQuery.htmlPrefilter` becomes an identity function (bundle patch), and the editor response carries a Content-Security-Policy (no `unsafe-inline`/`unsafe-eval` for scripts, nonce for the inline config script, hashes for the fixed dialog handlers) so handlers created by HTML parsing are inert (CVE-2020-11022, CVE-2020-11023); run `bin/console assets:install` and `bin/console cache:clear` |

All patches are verified on 10.6.9. Each patch file starts with a header (CVE, advisory, verified versions, summary).

### Not affected on 10.6.9

The vulnerable code is absent; the VEX lists these as `not_affected`.

- CVE-2026-27461: the dependency listing has no filter input and no `RLIKE`.
- CVE-2024-23646: both asset zip actions quote every `selectedId`.
- CVE-2023-49075: `PimcoreUserTwoFactorCondition` does not exist; two-factor runs through `TwoFactorListener` and `scheb/2fa-bundle`.
- CVE-2023-37280: the `/admin/login/2fa-setup` route does not exist.

CVE-2023-1247 is withdrawn by GitHub and not listed. PD-2026-001 (admin session token hardening of the 11.5 line) does not apply: `lib/Tool/Authentication.php` reads a session attribute and deserialises no token.

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
