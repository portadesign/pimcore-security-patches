<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final readonly class ComposerPlugin implements \Composer\Plugin\PluginInterface, \Composer\EventDispatcher\EventSubscriberInterface
{
    public function activate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    public function deactivate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    public function uninstall(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            \Composer\Script\ScriptEvents::POST_INSTALL_CMD => 'synchronize',
            \Composer\Script\ScriptEvents::POST_UPDATE_CMD => 'synchronize',
        ];
    }

    public function synchronize(\Composer\Script\Event $event): void
    {
        if (false !== \Composer\Util\Platform::getEnv(name: PatchCommandRunner::GUARD_ENV)) {
            return;
        }

        $composer = $event->getComposer();
        $patchesPlugin = $this->findPatchesPlugin(composer: $composer);
        if (null === $patchesPlugin) {
            return;
        }

        $disabledResolvers = $patchesPlugin->getConfig(key: 'disable-resolvers');
        $resolved = (new \cweagans\Composer\Resolver(
            composer: $composer,
            io: new \Composer\IO\NullIO(),
            disabledResolvers: is_array($disabledResolvers) ? $disabledResolvers : [],
        ))->loadFromResolvers();

        $io = $event->getIO();
        $reason = $this->detectDrift(patchesPlugin: $patchesPlugin, resolved: $resolved);

        if (null === $reason) {
            $inspection = $this->inspectInstalledPatches(composer: $composer, patchesPlugin: $patchesPlugin, io: $io);
            if ([] === $inspection['missing']) {
                if ($inspection['checked'] > 0) {
                    $io->write(messages: sprintf('pimcore-security-patches: all %d patches applied', $inspection['checked']));
                }

                return;
            }

            foreach ($inspection['missing'] as $package => $count) {
                $io->write(messages: sprintf('pimcore-security-patches: %d patch(es) missing in %s, re-applying', $count, $package));
            }
        } else {
            $io->write(messages: sprintf('pimcore-security-patches: %s, relocking and re-applying patches', $reason));
        }

        $patched = $this->installedPatchedPackages(composer: $composer, collection: $resolved);
        $output = $this->runPatchCommands(composer: $composer, io: $io, devMode: $event->isDevMode());
        $this->assertInstalled(composer: $composer, patchedPackages: $patched, output: $output);
        $this->assertPatched(composer: $composer, patchesPlugin: $patchesPlugin, io: $io, resolved: $resolved, patchedPackages: $patched, output: $output);
        $io->write(messages: sprintf(
            'pimcore-security-patches: patches applied to %s',
            [] === $patched ? 'no packages' : implode(separator: ', ', array: $patched),
        ));
    }

    /**
     * @return array{checked: int, missing: array<string, int>}
     */
    private function inspectInstalledPatches(
        \Composer\Composer $composer,
        \cweagans\Composer\Plugin\Patches $patchesPlugin,
        \Composer\IO\IOInterface $io,
        bool $reloadLock = false,
    ): array {
        $locker = $reloadLock ? new \cweagans\Composer\Locker($patchesPlugin->getLockFile()) : $patchesPlugin->getLocker();
        if (!$locker->isLocked()) {
            return ['checked' => 0, 'missing' => []];
        }

        $locked = \cweagans\Composer\PatchCollection::fromJson($locker->getLockData());
        $repository = $composer->getRepositoryManager()->getLocalRepository();
        $inspector = new InstalledPatchInspector(
            runner: new ComposerProcessRunner(executor: new \Composer\Util\ProcessExecutor($io)),
            download: static function (\cweagans\Composer\Patch $patch) use ($patchesPlugin): void {
                $patchesPlugin->download(patch: $patch);
            },
            io: $io,
            bundledDirectory: dirname(path: __DIR__) . '/patches',
        );
        $targets = [];

        foreach ($this->patchedPackages(collection: $locked) as $name) {
            $package = $repository->findPackage(name: $name, constraint: '*');
            $installPath = null === $package ? null : $composer->getInstallationManager()->getInstallPath(package: $package);
            if (null === $installPath) {
                continue;
            }

            $targets[$name] = [
                'installPath' => $installPath,
                'patches' => array_values(array: array_filter(
                    array: $locked->getPatchesForPackage(package: $name),
                    callback: static fn (mixed $patch): bool => $patch instanceof \cweagans\Composer\Patch,
                )),
            ];
        }

        return $inspector->inspectAll(targets: $targets);
    }

    private function findPatchesPlugin(\Composer\Composer $composer): ?\cweagans\Composer\Plugin\Patches
    {
        foreach ($composer->getPluginManager()->getPlugins() as $plugin) {
            if ($plugin instanceof \cweagans\Composer\Plugin\Patches) {
                return $plugin;
            }
        }

        return null;
    }

    private function detectDrift(\cweagans\Composer\Plugin\Patches $patchesPlugin, \cweagans\Composer\PatchCollection $resolved): ?string
    {
        $locker = $patchesPlugin->getLocker();
        $lockName = basename(path: $patchesPlugin->getLockFile()->getPath());

        if (!$locker->isLocked()) {
            return [] === $this->patchedPackages(collection: $resolved) ? null : sprintf('%s is missing', $lockName);
        }

        $locked = $this->index(collection: \cweagans\Composer\PatchCollection::fromJson($locker->getLockData()));
        $wanted = $this->index(collection: $resolved);

        if (array_keys($locked) !== array_keys($wanted)) {
            return sprintf('%s is out of date', $lockName);
        }

        foreach ($wanted as $key => $sha256) {
            if (null !== $sha256 && $sha256 !== $locked[$key]) {
                return sprintf('%s has a different checksum for a patch', $lockName);
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function patchedPackages(\cweagans\Composer\PatchCollection $collection): array
    {
        return array_values(array: array_filter(array: $collection->getPatchedPackages(), callback: 'is_string'));
    }

    /**
     * @return list<string>
     */
    private function installedPatchedPackages(\Composer\Composer $composer, \cweagans\Composer\PatchCollection $collection): array
    {
        $repository = $composer->getRepositoryManager()->getLocalRepository();

        return array_values(array: array_filter(
            array: $this->patchedPackages(collection: $collection),
            callback: static fn (string $name): bool => null !== $repository->findPackage(name: $name, constraint: '*'),
        ));
    }

    /**
     * @return array<string, string|null>
     */
    private function index(\cweagans\Composer\PatchCollection $collection): array
    {
        $index = [];
        foreach ($this->patchedPackages(collection: $collection) as $package) {
            foreach ($collection->getPatchesForPackage(package: $package) as $patch) {
                if (!$patch instanceof \cweagans\Composer\Patch) {
                    continue;
                }

                $index[$package . ' ' . $patch->url] = $patch->sha256 ?? null;
            }
        }
        ksort(array: $index);

        return $index;
    }

    private function runPatchCommands(\Composer\Composer $composer, \Composer\IO\IOInterface $io, bool $devMode): string
    {
        $composerBinary = \Composer\Util\Platform::getEnv(name: 'COMPOSER_BINARY');
        if (!is_string($composerBinary) || '' === $composerBinary) {
            throw new \RuntimeException('COMPOSER_BINARY is not set, cannot run the patches commands.');
        }

        $arguments = $_SERVER['argv'] ?? [];
        $runner = new PatchCommandRunner(
            runner: new ComposerProcessRunner(executor: new \Composer\Util\ProcessExecutor($io)),
            phpBinary: PHP_BINARY,
            composerBinary: $composerBinary,
            parentArguments: is_array($arguments) ? array_values(array: array_filter(array: $arguments, callback: 'is_string')) : [],
        );

        $cwd = getcwd();

        return $runner->run(
            cwd: false === $cwd ? dirname(path: $composer->getConfig()->getConfigSource()->getName()) : $cwd,
            devMode: $devMode,
        );
    }

    /**
     * @param list<string> $patchedPackages
     */
    private function assertInstalled(\Composer\Composer $composer, array $patchedPackages, string $output): void
    {
        $vendorDir = $composer->getConfig()->get(key: 'vendor-dir');
        if (!is_string($vendorDir)) {
            throw new \RuntimeException('vendor-dir is not configured.');
        }

        $installed = new \Composer\Repository\FilesystemRepository(
            repositoryFile: new \Composer\Json\JsonFile(path: $vendorDir . '/composer/installed.json'),
        );
        $installationManager = $composer->getInstallationManager();

        foreach ($patchedPackages as $name) {
            $package = $installed->findPackage(name: $name, constraint: '*');
            $installPath = null === $package ? null : $installationManager->getInstallPath(package: $package);
            if (null === $installPath || !is_file(filename: $installPath . '/composer.json')) {
                throw new \RuntimeException(sprintf(
                    "%s is missing after re-applying patches. Output of the patches commands:\n%s\nrun \"composer install\" to restore vendor/",
                    $name,
                    $output,
                ));
            }
        }
    }

    /**
     * @param list<string> $patchedPackages
     */
    private function assertPatched(
        \Composer\Composer $composer,
        \cweagans\Composer\Plugin\Patches $patchesPlugin,
        \Composer\IO\IOInterface $io,
        \cweagans\Composer\PatchCollection $resolved,
        array $patchedPackages,
        string $output,
    ): void {
        $lockFile = $patchesPlugin->getLockFile();
        $locker = new \cweagans\Composer\Locker($lockFile);
        $lockedKeys = $locker->isLocked()
            ? array_keys(array: $this->index(collection: \cweagans\Composer\PatchCollection::fromJson($locker->getLockData())))
            : [];
        $wantedKeys = array_keys(array: $this->index(collection: $resolved));
        if ($lockedKeys !== $wantedKeys) {
            throw new \RuntimeException(sprintf(
                "%s does not match the resolved patches after relocking. Output of the patches commands:\n%s",
                basename(path: $lockFile->getPath()),
                $output,
            ));
        }

        (new PatchInspectionGuard())->assertApplied(
            inspection: $this->inspectInstalledPatches(composer: $composer, patchesPlugin: $patchesPlugin, io: $io, reloadLock: true),
            patchesExpected: [] !== $patchedPackages,
            output: $output,
        );
    }
}
