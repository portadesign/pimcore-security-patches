# Agent context

Read this first. It explains why the package exists, how it works, which decisions are settled and what is open.

## Purpose

Pimcore 11 reached end of life with 11.5.14.1 (admin-ui-classic-bundle 1.7.16) while CVEs against it kept being published. Portadesign runs several Pimcore 11 projects (suys-pim11, stock, more) on the same base image (`portadev/pimcore-php`, Alpine, ships `git` and `patch`). This package carries Portadesign's own fixes for those CVEs, written from the public advisories and this package's regression tests, and applies them from Composer, so each project needs only `composer require` and gets the same patch set, verification and scanner silencing.

Public GitHub repository, not on Packagist. Installation is documented in `README.md` and must stay at a handful of copy-paste commands.

## Lines, branches, name

- Package `portadesign/pimcore-security-patches` (namespace `Portadesign\PimcoreSecurityPatches`). It replaces `portadesign/pimcore-11-security-patches`, whose tags v1.0.0–v1.0.3 stay untouched. The GitHub repository was renamed to `portadesign/pimcore-security-patches` on 2026-11-12; GitHub redirects the old path, which v11.5.0 still uses in its patch URLs and VEX `@id`.
- Versioned like Pimcore: one branch and one tag series per Pimcore line. Branch `11.5` (Pimcore 11.5.x, admin-ui-classic-bundle 1.7.x) releases `v11.5.<n>`; branch `10.6` (Pimcore 10.6.x, PHP 8.1) releases `v10.6.<n>`. A project requires `^11.5` or `^10.6`. `conflict` in each branch's `composer.json` pins its line. The 10.6 line exists; its patch list follows and is documented on that branch.
- `main` follows the newest line by fast-forward. A fix that applies to several lines is made per branch, not merged across: patches, tests and manifests differ per line.
- The `.github/workflows/verify.yml` matrix is per branch (the versions of that line). Scheduled workflows run only on the default branch, so the weekly run covers the line `main` points to.

## Provenance

Every patch is an independent implementation. The inputs were the public advisory text (GHSA/NVD), the GPLv3 Pimcore 11.5.4 and 11.5.14.1 sources and the exploit tests in `tests/`. No other implementation of a fix, no newer Pimcore release and no third-party fork was consulted. Keep it that way: a new patch starts from the advisory and a failing test, never from somebody else's diff. Do not add references to other implementations to patch headers, README, CHANGELOG or VEX.

## How it works

- `composer.json` is a `composer-plugin` that requires `cweagans/composer-patches` 2.x. Patches live in `patches/` and are referenced in `extra.patches` by raw GitHub URL pinned to the release tag plus `sha256`. cweagans reads dependency patches only from `composer.lock`, so the URLs must be absolute; relative vendor paths do not work.
- `src/ComposerPlugin.php` subscribes to `post-install-cmd` and `post-update-cmd`. `detectDrift()` compares `patches.lock.json` with the resolved patch set; `InstalledPatchInspector` checks that each locked patch is applied (`patch -R --dry-run`, fallback `git apply --check -R` with `GIT_CEILING_DIRECTORIES`; both missing → warning, no repatch). Drift or a missing patch triggers `patches-relock` and `patches-repatch` in a child Composer process (`PatchCommandRunner` over `ComposerProcessRunner`, in the project directory, forwarding `--ignore-platform-req[s]` as `COMPOSER_IGNORE_PLATFORM_REQ[S]`), guarded against recursion by `PORTADESIGN_PATCHES_SYNC`. Running cweagans in-process fails because Composer loads the plugin class twice. A non-zero child exit throws with the child output. After the run `PatchInspectionGuard` re-inspects every patch from the fresh lock and checks the patched package directories; it throws when a patch is still missing or when nothing could be verified (neither `patch` nor `git`), because `patches-repatch` in composer-patches 2 exits 0 even when its inner `install` fails.
- Bundled `patches/*` with a matching `sha256` are used for verification instead of a download; download failures warn and skip.
- `advisories.json` is the single source for advisory status. `bin/build-vex.php` generates `vex.openvex.json` (OpenVEX 0.2.0, for Trivy `--vex`) and `audit-ignore.json` (for Composer `config.audit.ignore` and `config.policy.advisories.ignore-id`). Statuses: `fixed`, `affected`, `not_affected` with precondition, `accepted` (not in the VEX, needs `.trivyignore.yaml`), `hardening` (no public advisory, internal `PD-YYYY-NNN` id, not in the VEX). Advisories without a PKSA id carry `ghsa`; their CVE and GHSA ids go into `audit-ignore.json`. Products are listed with and without the `v` prefix because Trivy takes the PURL version from `composer.lock` (`v11.5.14.1`).
- `release.sh <line>.<n> [--dry-run]` runs on a line branch (`11.5.0` on `11.5`; any other version, a non-line branch, a detached HEAD, an existing tag, an HTTPS `origin` or a dirty tracked tree is refused). It runs `phpunit.unit.xml.dist` and `verify.sh` for every pimcore × admin combination of `.github/workflows/verify.yml`, aborting on a failure, then rewrites patch URLs to the tag, regenerates hashes (`bin/sync-patch-hashes.php`) and the VEX, commits, tags and pushes branch and tag atomically. `main` is fast-forwarded and pushed too when it is an ancestor of HEAD and the branch is the newest line (a later line forked from an older one has `main` as ancestor as well). `--dry-run` runs the checks and prints the remaining steps; it changes nothing. Push over SSH; the HTTPS OAuth token lacks the `workflow` scope.
- `verify.sh [pimcore-tag] [admin-tag]` applies every patch to pristine release tarballs (needs `gh`); `.github/workflows/verify.yml` runs it on push, PR and weekly for the 11.5.4/11.5.14.1 × 1.7.6/1.7.16 matrix.

## Tests

- `tests/*Test.php`: exploit regression tests, one group per CVE. They need a host project with a database. Run inside the project container: copy the repo (without `vendor/`) into the project, e.g. `var/tmp/security-patches`, then `PIMCORE_PROJECT_ROOT=/app vendor/bin/phpunit -c var/tmp/security-patches/phpunit.xml.dist`. Last run (2026-11-10, all branch patches applied to scratch copies of pimcore 11.5.14.1 and admin-ui-classic-bundle 1.7.16 mounted over stock's vendor, `php -d memory_limit=3G`): 812 tests green, PHP 8.3.36; stock itself installs the released tag, so the unreleased patches have to be swapped in for a green run. Earlier: 577 on suys-pim11 (11.5.4, v1.0.2). Reverting a patch with `patch -R` can leave `*.orig` files; run `find vendor/pimcore -name '*.orig' -delete` afterwards. Revert checks without touching the host's vendor: extract the pristine tarballs, apply the patches in `composer.json` order (`git apply`), omit the patch under test and mount the tree over `vendor/pimcore/pimcore` with `docker compose run --rm --no-deps -v <tree>:/app/vendor/pimcore/pimcore --entrypoint "" app php vendor/bin/phpunit ...`. Red counts (2026-11-10): CVE-2026-11407 188 of 199 (`TwigSandboxTest`, `TwigSandboxMutatorTest`), CVE-2026-55220 49 of 80 and CVE-2026-45162 pimcore part 29 of 80 (`UnserializeHardeningTest`, `UnserializeRemainingPathsTest`), CVE-2026-58401 (`Authentication.php` hunk only, the Configuration hunk is needed to boot) 16 of 25. Hosts set `SET time_zone` to PHP's offset in `TranslationGridFilterTest`. Running them from the host without a database produces hundreds of errors; that is not a regression.
- `tests/Unit`: plugin unit tests, `vendor/bin/phpunit -c phpunit.unit.xml.dist`, no host needed.
- `composer phpstan` must be clean.

## Settled decisions

- Every advisory is patched; nothing is accepted or skipped. WebDAV must stay fully functional, no proxy precondition (owner decision 2026-11-03).
- The VEX tells the truth: a CVE is `fixed` only when every path in its advisory is patched.
- Verification runs on every install; the cost of downloading is avoided by the bundled files.
- No Packagist publication; vcs repository line in the README.
- Patches are independent implementations (see Provenance); the repository history starts at v1.0.0 of 2026-11-02.

## Open items (reviewer backlog, non-blocking)

1. `composer.json` conflict range allows unverified enterprise releases ≥ 11.5.15 / admin-ui ≥ 1.7.17; VEX lists only 11.5.4 and 11.5.14.1, so Trivy will not match 11.5.5–11.5.13. List every version or verify them with `verify.sh`.
2. If cweagans is not active (not allowed, or 1.x) the plugin returns silently; print an error.
3. The child `install` dumps a non-optimized autoloader over the parent's `-o`/`-a` one and runs under Composer's 300 s process timeout.
4. Two data providers in `tests/ClassDefinitionIdentifierTest.php` are empty on a host without classes or reports.
5. CVE-2026-45703: elements without `view` permission are skipped silently (200, element omitted); no 403.
6. `ComposerPlugin` itself has no unit test.
7. Characterisation tests that cannot fail against the patches: the assignment-path cases in `tests/CompositeIndexTest.php` and the `tests/CompositeIndexLegacyKeyTest.php` load test are guards that fail only if a patch starts validating on assignment or load. The signed-length class names (PHP 8.3 rejects them itself) were replaced by zero-padded lengths and signed property counts/keys, which PHP accepts; `TwigSandboxTest` no longer accepts a `TypeError` (the CVE-2026-11407 patch fixes the message cut in `Mail::renderParams()`). Exploit tests leave orphan `versions` rows on the host; run the versions cleanup afterwards.
8. CustomReports `downloadCsvAction` serves any `report-export-<uniqid>.csv` from the temp dir by name; bind export names to the session (reviewer finding on CVE-2026-45704).

## Conventions

`declare(strict_types=1)`, FQCN without `use`, named arguments, `readonly`, no comments. Conventional Commits, no tool attribution. Every change gets a line in `docs/CHANGELOG.md` (newest on top, local date and time). Never read `.env*` of a host project.

## Related

- Projects: `suys-pim11` (branch `feat/php83`), `stock` (11.5.14.1, cweagans 2).
- `portadesign/docker-library` PR #6 pins `git` and `patch` in `pimcore-php`.
- [`security-txt`](https://github.com/portadesign/security-txt): Composer package creating and checking security.txt; unrelated to patches.
