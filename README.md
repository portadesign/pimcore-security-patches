# pimcore-security-patches

Security patches for `pimcore/pimcore` 11.5.4–11.5.14.1 and `pimcore/admin-ui-classic-bundle` 1.7.6–1.7.16, applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

## Install

Needs Composer 2 and PHP ≥ 8.2. Not on Packagist.

```bash
composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer config allow-plugins.cweagans/composer-patches true
composer config allow-plugins.portadesign/pimcore-security-patches true
composer require portadesign/pimcore-security-patches:^11.5
bin/console cache:clear
```

Commit `composer.json`, `composer.lock` and `patches.lock.json`. Every `composer install`/`update` verifies the patches and re-applies them when needed.

- Composer 2.10+ blocks `pimcore/pimcore` because of open advisories: put the `config.policy` part of `audit-ignore.json` into `composer.json` before `composer require`.
- Project on `cweagans/composer-patches` 1.x: `composer remove cweagans/composer-patches`, delete `patches.lock.json`, then the steps above.

## Versions

One branch and one tag series per Pimcore line; the version is the line: `^11.5` never installs a 10.6 patch set.

| Pimcore | Branch | Tags | Require |
| --- | --- | --- | --- |
| 10.6.x | `10.6` | `v10.6.<n>` | `^10.6` |
| 11.5.x | `11.5` | `v11.5.<n>` | `^11.5` |

`portadesign/pimcore-11-security-patches` v1.0.x is superseded. Migration from it:

```bash
composer remove portadesign/pimcore-11-security-patches
composer config allow-plugins.portadesign/pimcore-11-security-patches --unset && composer config allow-plugins.portadesign/pimcore-security-patches true
composer require portadesign/pimcore-security-patches:^11.5
```

## Patches

| CVE | Package | What changes |
| --- | --- | --- |
| CVE-2026-27461 | pimcore | Dependency filter value is bound as a parameter (literal substring match, no `RLIKE`) |
| CVE-2026-55634 | pimcore | `Data::setName()` accepts only `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`; classification store key names stay free text |
| CVE-2026-11407 | pimcore | Twig sandbox policy: blocked classes (user, token, session, request bags, DAO, listings, DBAL, PDO, container, kernel, process, Twig, class/brick/field-collection/custom-layout definitions), blocked `pimcore_*` functions (files, dumps, render state, navigation, editables), request readers and mutators, workflow, translator and catalogue mutators, no magic or static calls or `__call` forwarding on models, hard-blocked mutators (`save*`, `delete*`, `set*`, …) and secret getters. `objectTypes` arguments restricted to object/variant/folder; array thumbnail configs rejected in a sandbox; the CSRF token and CSP handler are not readable. Needs `twig/twig` >= 3.27.0 (Composer conflict below it, sandbox state and `__toString`/ArrayAccess checks). Config: `pimcore.templating_engine.twig.sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}` |
| CVE-2026-5394 | pimcore | Composite index keys `^[a-zA-Z0-9_+-]{1,64}$` and columns `^[a-zA-Z][a-zA-Z0-9_-]{0,63}$` checked before SQL; empty key skipped with a warning |
| CVE-2026-44739 | pimcore | Custom report SQL keyword guard sees through comments |
| CVE-2026-55416 | pimcore | Report fragments may not contain `;`, `#`, `--`, `/* */`, `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE(` outside quotes or start with a write statement; filter/sort/drill-down fields are quoted |
| CVE-2026-55220, CVE-2026-45162 | pimcore | `unserialize()` with class allowlists where data comes from the database or files (Site, CustomLayout, TmpStore, Hotspotimage, WebDAV delete log, Table, Block, editables, Link, Geo, asset custom settings, SEO error log); Version, Recyclebin, Hardlink upcast and EncryptedField stay unrestricted by design. Session elements in `tmp_store` are HMAC-signed, so editors open during the deploy lose unsaved edits once. Config: `pimcore.tmp_store.unserialize_allowed_classes`. Legacy Block/Video data or custom settings holding other objects load as incomplete classes; a WebDAV delete-log entry holding other objects is dropped, so the restore creates an asset with a new ID |
| PD-2026-001 (no CVE, hardening) | pimcore | Admin session token class allowlist. Config: `pimcore.security.session_token_allowed_classes` |
| CVE-2026-55072 | pimcore | Class definition ID regex anchored (`/D`), name checked, `Block::load()` quotes table names |
| CVE-2026-45260 | pimcore | WebDAV MOVE needs `create` on the destination, `publish` on the asset, `delete` when overwriting/restoring, `rename` for a rename; checks run in a Sabre `beforeMove` plugin before the destination is deleted; an existing destination folder needs `rename`, a taken target path or a cross-folder move onto a destination of another name returns 409; a failed save returns 500 |
| CVE-2026-45703 | pimcore | WordExport skips elements the user may not `view` (no 403) |
| CVE-2026-45704 | pimcore | Custom report detail, data, chart, drill-down and CSV endpoints enforce the listing sharing rule; `reports_config` users and admins keep full access |
| CVE-2026-115898 | admin-ui-classic-bundle, pimcore | The lost-password and login invitation mails (reset link with the request-derived base URL) are sent without template rendering, so template code placed in `X-Forwarded-Prefix` is no longer executed; the workflow notification deeplink percent-encodes characters outside `A-Za-z0-9/._~%` of the base URL |
| CVE-2026-44741 | admin-ui-classic-bundle | Translation grid filter: column allowlist, quoted identifiers |
| CVE-2026-45162 | admin-ui-classic-bundle | Dashboard config deserialised without classes |
| PD-2026-007 (no CVE, hardening) | admin-ui-classic-bundle | Object grid sort on a classification store column: field must be a classification store field of the class, group and key ids must be integers, otherwise `InvalidArgumentException` |

All patches are verified on 11.5.4, 11.5.14.1 / 1.7.6, 1.7.16. Each patch file starts with a header (CVE, advisory, verified versions, summary).

## Scanners

- Composer: copy `audit-ignore.json` into `composer.json` `config` (`audit.ignore`, and `policy.advisories.ignore-id` on 2.10+).
- Trivy: `vex.openvex.json` (OpenVEX, matches the `composer.lock` PURL with and without the `v` prefix) hides every CVE above.

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

- `./verify.sh [pimcore-tag] [admin-ui-tag]`: every patch applies to pristine release tarballs (needs `gh`); CI runs it on push and weekly.
- New patch: failing test in `tests/`, patch with header, entry in `extra.patches`, table row, `./verify.sh`.
- Status in `advisories.json`; `php bin/build-vex.php` regenerates `vex.openvex.json` and `audit-ignore.json`.
- Release: `./release.sh <line>.<n> [--dry-run]` on the line branch (e.g. `11.5.0` on `11.5`). Needs a clean tree, runs the unit tests and `verify.sh` for every combination in `.github/workflows/verify.yml`, pins patch URLs to the tag, syncs `sha256`, rebuilds the VEX, commits, tags and pushes branch and tag over SSH; fast-forwards `main` when this is the newest line.

## Tests

Exploit tests need a host project with a database (dist install omits `tests/`: clone the repo or `composer reinstall portadesign/pimcore-security-patches --prefer-source`). They create and remove their own fixtures.

```bash
T="-c vendor/portadesign/pimcore-security-patches/phpunit.xml.dist"; vendor/bin/phpunit $T
(cd vendor/pimcore/pimcore && git apply -R ../../portadesign/pimcore-security-patches/patches/pimcore-CVE-2026-27461-dependency-rlike.patch) && vendor/bin/phpunit $T --group CVE-2026-27461   # must fail
composer patches-repatch && vendor/bin/phpunit $T --group CVE-2026-27461   # must pass
```

Plugin unit tests: `vendor/bin/phpunit -c phpunit.unit.xml.dist`.
