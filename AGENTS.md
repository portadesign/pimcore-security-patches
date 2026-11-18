# Agent context

Read this first. It explains why the package exists, how it works, which decisions are settled and what is open.

## Purpose

This is the Pimcore 10.6 line. Pimcore 10 is end of life: 10.6.9 is the last release (PHP 8.1) while CVEs against it keep being published, and the admin UI lives inside `pimcore/pimcore` (`bundles/AdminBundle`), not in `pimcore/admin-ui-classic-bundle`. Portadesign runs Pimcore 10 projects on the same base image as the 11 ones (`portadev/pimcore-php`, Alpine, ships `git` and `patch`). This package carries Portadesign's own fixes for those CVEs, written from the public advisories and this package's regression tests, and applies them from Composer, so each project needs only `composer require` and gets the same patch set, verification and scanner silencing.

The patch list is the table in `README.md` (patch files in `patches/`, apply order in `composer.json` `extra.patches`, each file's header names the ids, advisory, verified version and summary); `advisories.json` holds the status per advisory. A patch was written against 10.6.9 from the advisory and a failing test; the 11.5 branch is only the pattern for the plugin and the test conventions (`git show 11.5:<path>`).

Public GitHub repository, not on Packagist. Installation is documented in `README.md` and must stay at a handful of copy-paste commands.

## Lines, branches, name

- Package `portadesign/pimcore-security-patches` (namespace `Portadesign\PimcoreSecurityPatches`). It replaces `portadesign/pimcore-11-security-patches`, whose tags v1.0.0–v1.0.3 stay untouched. The GitHub repository was renamed to `portadesign/pimcore-security-patches` on 2026-11-13; patch URLs, `release.sh` and the VEX `@id` use that path.
- Versioned like Pimcore: one branch and one tag series per Pimcore line. Branch `11.5` (Pimcore 11.5.x, admin-ui-classic-bundle 1.7.x) releases `v11.5.<n>`; branch `10.6` (Pimcore 10.6.x, PHP 8.1) releases `v10.6.<n>`. A project requires `^11.5` or `^10.6`. `conflict` in each branch's `composer.json` pins its line; on this branch `pimcore/pimcore: <10.6.9 || >=10.7` and no admin-ui conflict.
- `main` follows the newest line by fast-forward. A fix that applies to several lines is made per branch, not merged across: patches, tests and manifests differ per line.
- The `.github/workflows/verify.yml` matrix is per branch (here `pimcore: [v10.6.9]`). Scheduled workflows run only on the default branch, so the weekly run covers the line `main` points to.

## Provenance

Every patch is an independent implementation. The inputs were the public advisory text (GHSA/NVD), the GPLv3 Pimcore 10.6.9 source (and, to understand what this repository's own 11.5 patches target, the 11.5.4 and 11.5.14.1 sources) and the exploit tests in `tests/`. No other implementation of a fix, no newer Pimcore release and no third-party fork was consulted. Keep it that way: a new patch starts from the advisory and a failing test, never from somebody else's diff. Do not add references to other implementations to patch headers, README, CHANGELOG or VEX.

## How it works

- `composer.json` is a `composer-plugin` that requires `cweagans/composer-patches` 2.x and PHP `^8.1`; Pimcore 10 projects often run 1.x, see the migration steps in `README.md`. Patches live in `patches/` and are referenced in `extra.patches` by raw GitHub URL pinned to the release tag plus `sha256`. cweagans reads dependency patches only from `composer.lock`, so the URLs must be absolute; relative vendor paths do not work.
- `src/ComposerPlugin.php` subscribes to `post-install-cmd` and `post-update-cmd`. `detectDrift()` compares `patches.lock.json` with the resolved patch set; `InstalledPatchInspector` checks that each locked patch is applied (`patch -R --dry-run`, fallback `git apply --check -R` with `GIT_CEILING_DIRECTORIES`; both missing → warning, no repatch). Drift or a missing patch triggers `patches-relock` and `patches-repatch` in a child Composer process (`PatchCommandRunner` over `ComposerProcessRunner`, in the project directory, forwarding `--ignore-platform-req[s]` as `COMPOSER_IGNORE_PLATFORM_REQ[S]`), guarded against recursion by `PORTADESIGN_PATCHES_SYNC`. Running cweagans in-process fails because Composer loads the plugin class twice. A non-zero child exit throws with the child output. After the run `PatchInspectionGuard` re-inspects every patch from the fresh lock and checks the patched package directories; it throws when a patch is still missing or when nothing could be verified (neither `patch` nor `git`), because `patches-repatch` in composer-patches 2 exits 0 even when its inner `install` fails.
- Bundled `patches/*` with a matching `sha256` are used for verification instead of a download; download failures warn and skip.
- `advisories.json` is the single source for advisory status. `bin/build-vex.php` generates `vex.openvex.json` (OpenVEX 0.2.0, for Trivy `--vex`) and `audit-ignore.json` (for Composer `config.audit.ignore` and `config.policy.advisories.ignore-id`). Statuses: `fixed`, `affected`, `not_affected` with precondition, `accepted` (not in the VEX, needs `.trivyignore.yaml`), `hardening` (no public advisory, internal `PD-YYYY-NNN` id, not in the VEX). Advisories without a PKSA id carry `ghsa`; their CVE and GHSA ids go into `audit-ignore.json` and the GHSA id into the VEX aliases. Products are listed with and without the `v` prefix because Trivy takes the PURL version from `composer.lock` (`v10.6.9`). On this branch the only product is `pimcore/pimcore` 10.6.9; the admin UI is part of it.
- `release.sh <line>.<n> [--dry-run]` runs on a line branch (`11.5.0` on `11.5`; any other version, a non-line branch, a detached HEAD, an existing tag, an HTTPS `origin` or a dirty tracked tree is refused). It runs `phpunit.unit.xml.dist` and `verify.sh` for every tag of the `.github/workflows/verify.yml` matrix, aborting on a failure, then rewrites patch URLs to the tag, regenerates hashes (`bin/sync-patch-hashes.php`) and the VEX, commits, tags and pushes branch and tag atomically. `main` is fast-forwarded and pushed too when it is an ancestor of HEAD and the branch is the newest line (a later line forked from an older one has `main` as ancestor as well). `--dry-run` runs the checks and prints the remaining steps; it changes nothing. Push over SSH; the HTTPS OAuth token lacks the `workflow` scope.
- `verify.sh [pimcore-tag]` (default `v10.6.9`) applies every patch to the pristine release tarball (needs `gh`) and reports "no patches listed" while the list is empty; `.github/workflows/verify.yml` runs it on push, PR and weekly for `v10.6.9`.
- PHP 8.1 syntax only in `src/`, `bin/`, `tests/Support`, `tests/Unit` and the patched Pimcore code: no `readonly class`, trait constants, DNF types, standalone `true`/`false`/`null` types or `#[\Override]`; `readonly` goes on promoted properties. `phpstan.neon` sets `phpVersion: 80100`; PHPUnit is `^10.5` (its PHP 8.1 ceiling).

## Tests

- `tests/*Test.php`: exploit regression tests, one group per CVE or internal id (`--group <id>`). They need a host project with a database: a disposable Pimcore 10.6.9 install (demo v10.3.5, `portadev/pimcore-php` PHP 8.1, or 8.2 with `config.platform.php` 8.1.99 as the consumers run it) with PHPUnit 10.5 and `twig/twig` ^3.27, pristine `vendor/`, no `portadesign/*` package (a Docker Compose project with `app` and `db` services; keep its README next to it with start/stop, the rsync of this repo without `vendor/`, `.git` and `.phpunit.cache` into `var/tmp/security-patches`, and the `patch -p1` apply/revert commands). Run `PIMCORE_PROJECT_ROOT=<app root> vendor/bin/phpunit -c var/tmp/security-patches/phpunit.xml.dist [--group <id>]`, then remove the copy and `.phpunit.cache`. Run the suite unpatched (most tests must fail) and patched (all green, the minipaint node tests skip without `node`).
- The host needs `league/csv` below 9.11 (`composer require 'league/csv:9.8.0' -W` while testing, restore the lock afterwards): 9.11+ breaks pristine `CsvFormulaFormatter`, see `README.md`.
- Tests that create assets, documents, versions or admin translations use `tests/Support/HostResidueGuard` (disables versions, removes only the rows of elements the test created: versions with `cid` above the highest element id at test start, messenger messages whose element id is above it; drops queued admin translations). Messages of other classes survive; set `PD_TEST_HOST_DISPOSABLE=1` on a disposable host to also delete every `messenger_messages` row created since the test started. Never set it on a project host with a live worker. A full run must leave the row counts of `versions`, `messenger_messages`, `translations_admin`, `objects`, `assets`, `documents`, `users` and the files under `var/` unchanged; compare counts before and after. Asset objects returned by `Asset::getByPath()` after an out-of-process request can be stale in the runtime cache: reload with `Asset::getById($id, ['force' => true])`.
- 10.6 differs from 11.5: custom reports live in core (`Pimcore\Model\Tool\CustomReport`, not a bundle), the admin UI is `bundles/AdminBundle` inside `pimcore/pimcore`, PHPUnit stops at 10.5, and the demo has no reports (tests create their own). Clear `var/cache` after every apply or revert; reverting with `patch -R` can leave `*.orig` files (`find vendor/pimcore -name '*.orig' -delete`). Running them from the host without a database produces hundreds of errors; that is not a regression.
- `tests/Unit`: plugin unit tests, `vendor/bin/phpunit -c phpunit.unit.xml.dist`, no host needed; run them on PHP 8.1 too (the host container, `composer install` in a copy).
- `composer phpstan` must be clean.

## Settled decisions

- Every advisory that affects 10.6.9 is patched; nothing is accepted or skipped. WebDAV must stay fully functional, no proxy precondition (owner decision 2026-11-03).
- The VEX tells the truth: a CVE is `fixed` only when every path in its advisory is patched.
- Verification runs on every install; the cost of downloading is avoided by the bundled files.
- No Packagist publication; vcs repository line in the README.
- Patches are independent implementations (see Provenance); the repository history starts at v1.0.0 of 2026-11-02.
- This line is PHP 8.1 and Pimcore 10.6.9 only; nothing from the 11.5 branch is merged, it is ported per patch.

## Open items

1. The PDF preview (CVE-2023-46722) sets the request attribute `_pimcore_own_csp`, honoured by `AdminSecurityListener` through the image editor CSP patch: the P5 PDF patch needs the P6 CSP patch applied first (composer order).
2. `composer.json` conflict range allows unverified enterprise releases of 10.6.9+ below 10.7; the VEX lists only 10.6.9. Verify the others with `verify.sh` or narrow the range.
3. If cweagans is not active (not allowed, or 1.x) the plugin returns silently; print an error. Matters more here, as Pimcore 10 projects often start on 1.x.
4. The child `install` dumps a non-optimized autoloader over the parent's `-o`/`-a` one and runs under Composer's 300 s process timeout.
5. `ComposerPlugin` itself has no unit test.
6. `bundles/AdminBundle/Helper/QueryParams.php:122` concatenates `$f->property` unquoted in its date branch; nothing in 10.6.9 calls `QueryParams::getFilterCondition()`, so it is not patched. Project code calling it stays exposed.
7. Document-based mails still render their output a second time (core design); PD-2026-008 encodes every template start outside the document's own editables before that pass, so placeholders inside embedded snippets or renderlets are no longer evaluated.
8. CVE-2026-45162: deeply nested pricing `Bracket` conditions in a stored rule can exhaust resources when loaded (allowlist does not bound depth); `Serialize::unserializeSubtypes()` autoloads identifier-shaped class names found in the stored data, so any autoloadable class name is loaded (never instantiated unless it extends an allowed base type).
9. Browser behaviour is verified manually only: the image editor CSP (GHSA-jmh9-6rjq-gjh9) and the PDF preview (CSP and nosniff in the native PDF viewers of Chrome, Firefox, Safari). The tests assert the response headers. The minipaint jQuery probe (`tests/js`, run by `MinipaintJqueryTest` and `verify.sh`) skips without `node`, so a host or CI without node does not run it.
10. Characterisation tests that cannot fail against the patches: signed-length payloads in `tests/Support/RejectedSerializedPayloads.php`, the `testControl*` cases by design.
11. CVE-2026-45260: with `delete` but without `rename`, an overwrite whose destination was already deleted by Sabre and whose delete-log entry is lost ends as a rename of the source onto the destination path (authorised by the `beforeMove` decision). A cross-folder move to a free but different name still lands under the source name (core behaviour).
12. `models/DataObject/Listing/Concrete.php:178` does not check that `Fieldcollection\Definition::getByKey()` found the field collection type: the type goes unquoted into the join table name (`models/DataObject/Listing/Concrete/Dao.php:177`), and `getByKey()` builds the definition include path from it (`models/DataObject/Fieldcollection/Definition.php:114`, included at `:117`). No 10.6.9 core caller passes request data to `addFieldCollection()`, so it is not patched; project code passing request data stays exposed.

## Conventions

`declare(strict_types=1)`, FQCN without `use`, named arguments, `readonly`, no comments. Conventional Commits, no tool attribution. Every change gets a line in `docs/CHANGELOG.md` (newest on top, local date and time). Never read `.env*` of a host project.

## Related

- Projects on the 11.5 line: `suys-pim11` (branch `feat/php83`), `stock` (11.5.14.1, cweagans 2). No Pimcore 10 project is wired to this branch yet.
- `portadesign/docker-library` PR #6 pins `git` and `patch` in `pimcore-php`.
- [`security-txt`](https://github.com/portadesign/security-txt): Composer package creating and checking security.txt; unrelated to patches.
