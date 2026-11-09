<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final readonly class InstalledPatchInspector
{
    private const COMMAND_NOT_FOUND = 127;

    /**
     * @param \Closure(\cweagans\Composer\Patch): void $download
     */
    public function __construct(
        private ProcessRunner $runner,
        private \Closure $download,
        private \Composer\IO\IOInterface $io,
        private string $bundledDirectory,
    ) {
    }

    /**
     * @param array<string, array{installPath: string, patches: list<\cweagans\Composer\Patch>}> $targets
     *
     * @return array{checked: int, missing: array<string, int>}
     */
    public function inspectAll(array $targets): array
    {
        $checked = 0;
        $missing = [];
        $toolsUnavailable = false;

        foreach ($targets as $package => $target) {
            foreach ($target['patches'] as $patch) {
                $status = $this->inspect(patch: $patch, installPath: $target['installPath']);

                if (PatchStatus::Unverified === $status) {
                    continue;
                }

                if (PatchStatus::ToolsUnavailable === $status) {
                    $toolsUnavailable = true;

                    continue;
                }

                ++$checked;
                if (PatchStatus::Missing === $status) {
                    $missing[$package] = ($missing[$package] ?? 0) + 1;
                }
            }
        }

        if ($toolsUnavailable) {
            $this->io->writeError(messages: 'pimcore-security-patches: neither patch nor git found, cannot verify patches');
        }

        return ['checked' => $checked, 'missing' => $missing];
    }

    public function inspect(\cweagans\Composer\Patch $patch, string $installPath): PatchStatus
    {
        if (!$this->resolveLocalPath(patch: $patch)) {
            return PatchStatus::Unverified;
        }

        $file = $patch->localPath ?? '';
        $strip = '-p' . ($patch->depth ?? 1);

        $exitCode = $this->runner->run(
            command: ['patch', $strip, '--dry-run', '-R', '-s', '-f', '--batch', '-i', $file],
            cwd: $installPath,
        );
        if (self::COMMAND_NOT_FOUND !== $exitCode) {
            return 0 === $exitCode ? PatchStatus::Applied : PatchStatus::Missing;
        }

        $exitCode = $this->runner->run(
            command: ['git', 'apply', '--check', '-R', $strip, $file],
            cwd: $installPath,
            env: ['GIT_CEILING_DIRECTORIES' => dirname(path: $installPath)],
        );
        if (self::COMMAND_NOT_FOUND === $exitCode) {
            return PatchStatus::ToolsUnavailable;
        }

        return 0 === $exitCode ? PatchStatus::Applied : PatchStatus::Missing;
    }

    private function resolveLocalPath(\cweagans\Composer\Patch $patch): bool
    {
        $bundled = $this->bundledPath(patch: $patch);
        if (null !== $bundled) {
            $patch->localPath = $bundled;

            return true;
        }

        try {
            ($this->download)($patch);
        } catch (\Throwable $exception) {
            $this->io->writeError(messages: sprintf(
                'pimcore-security-patches: cannot download %s, skipping its verification: %s',
                $patch->url,
                $exception->getMessage(),
            ));

            return false;
        }

        return isset($patch->localPath);
    }

    private function bundledPath(\cweagans\Composer\Patch $patch): ?string
    {
        $expected = $patch->sha256 ?? null;
        if (null === $expected || '' === $expected) {
            return null;
        }

        $path = $this->bundledDirectory . '/' . basename(path: (string) parse_url(url: $patch->url, component: PHP_URL_PATH));
        if (!is_file(filename: $path)) {
            return null;
        }

        return hash_file(algo: 'sha256', filename: $path) === $expected ? $path : null;
    }
}
