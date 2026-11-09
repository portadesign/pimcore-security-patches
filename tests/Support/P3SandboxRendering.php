<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P3SandboxRendering
{
    protected function sandboxEngine(): \Pimcore\Templating\TwigDefaultDelegatingEngine
    {
        $engine = \Pimcore::getContainer()->get('pimcore.templating.engine.delegating');
        \assert($engine instanceof \Pimcore\Templating\TwigDefaultDelegatingEngine);

        return $engine;
    }

    protected function disableSandbox(): void
    {
        $this->sandboxEngine()->disableSandboxExtensionFromTwigEnvironment();
    }

    /**
     * @param array<string, mixed> $context
     */
    protected function renderSandboxed(string $template, array $context = []): string
    {
        return $this->sandboxEngine()->getTwigEnvironment(true)->createTemplate($template)->render($context);
    }

    /**
     * @param class-string<\Twig\Sandbox\SecurityError> $expectedError
     * @param array<string, mixed> $context
     */
    protected function assertSandboxBlocks(string $template, string $expectedError, array $context = []): void
    {
        try {
            $rendered = $this->renderSandboxed($template, $context);
        } catch (\Twig\Sandbox\SecurityError $error) {
            $this->assertInstanceOf($expectedError, $error, 'wrong sandbox error for ' . $template);

            return;
        } catch (\Throwable $error) {
            $this->fail(sprintf('%s was not blocked by the sandbox, got %s: %s', $template, $error::class, $error->getMessage()));
        }

        $this->fail(sprintf('%s was not blocked by the sandbox, it rendered %s', $template, var_export($rendered, true)));
    }
}
