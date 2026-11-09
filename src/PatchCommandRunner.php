<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final class PatchCommandRunner
{
    public const GUARD_ENV = 'PORTADESIGN_PATCHES_SYNC';

    private const COMMANDS = ['patches-relock', 'patches-repatch'];

    public const IGNORE_ALL_ENV = 'COMPOSER_IGNORE_PLATFORM_REQS';

    public const IGNORE_LIST_ENV = 'COMPOSER_IGNORE_PLATFORM_REQ';

    private const IGNORE_ALL_OPTION = '--ignore-platform-reqs';

    private const IGNORE_LIST_OPTION = '--ignore-platform-req';

    /**
     * @param list<string> $parentArguments
     */
    public function __construct(
        private readonly ProcessRunner $runner,
        private readonly string $phpBinary,
        private readonly string $composerBinary,
        private readonly array $parentArguments,
    ) {
    }

    /**
     * Runs the composer-patches relock and repatch commands and returns their combined output.
     *
     * @throws \RuntimeException when a command exits non-zero
     */
    public function run(string $cwd, bool $devMode): string
    {
        $env = [self::GUARD_ENV => '1', ...$this->platformEnvironment()];
        if (!$devMode) {
            $env['COMPOSER_NO_DEV'] = '1';
        }

        $output = '';
        foreach (self::COMMANDS as $command) {
            $exitCode = $this->runner->run(
                command: [$this->phpBinary, $this->composerBinary, $command, '--no-scripts', '--no-interaction'],
                cwd: $cwd,
                env: $env,
            );
            $output .= $this->runner->lastOutput();
            if (0 !== $exitCode) {
                throw new \RuntimeException(sprintf(
                    "composer %s failed with exit code %d:\n%s%s",
                    $command,
                    $exitCode,
                    $output,
                    'patches-repatch' === $command ? "\nrun \"composer install\" to restore vendor/" : '',
                ));
            }
        }

        return $output;
    }

    /**
     * @return array<non-empty-string, string>
     */
    public function platformEnvironment(): array
    {
        $ignoreAll = false;
        $ignored = [];
        $arguments = $this->parentArguments;
        $count = count($arguments);
        $inlinePrefix = self::IGNORE_LIST_OPTION . '=';

        for ($i = 0; $i < $count; $i++) {
            $argument = $arguments[$i];
            if ('--' === $argument) {
                break;
            }

            if (self::IGNORE_ALL_OPTION === $argument) {
                $ignoreAll = true;

                continue;
            }

            if (self::IGNORE_LIST_OPTION === $argument) {
                if (isset($arguments[$i + 1]) && !str_starts_with($arguments[$i + 1], '-')) {
                    $ignored[] = $arguments[++$i];
                }

                continue;
            }

            if (str_starts_with($argument, $inlinePrefix) && strlen($argument) > strlen($inlinePrefix)) {
                $ignored[] = substr($argument, strlen($inlinePrefix));
            }
        }

        $env = [];
        if ($ignoreAll) {
            $env[self::IGNORE_ALL_ENV] = '1';
        }

        if ([] !== $ignored) {
            $env[self::IGNORE_LIST_ENV] = implode(',', array_values(array_unique($ignored)));
        }

        return $env;
    }
}
