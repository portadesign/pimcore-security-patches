<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxThumbnailTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    protected function tearDown(): void
    {
        $this->disableSandbox();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function arrayThumbnailProvider(): array
    {
        return [
            'new style array config' => ["{{ image.getThumbnail({'items': []}).getConfig().getFormat() }}"],
            'new style array config with a transformation' => ["{{ image.getThumbnail({'items': [{'method': 'addOverlay', 'arguments': {'image': '../../../../etc/hostname'}}]}).getConfig().getFormat() }}"],
            'legacy array config' => ["{{ image.getThumbnail({'width': 100}).getConfig().getFormat() }}"],
            'thumbnail config helper' => ["{{ image.getThumbnailConfig({'width': 100}).getFormat() }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('arrayThumbnailProvider')]
    public function testArrayThumbnailConfigIsBlockedInsideTheSandbox(string $template): void
    {
        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityError::class, ['image' => new \Pimcore\Model\Asset\Image()]);
    }

    public function testControlNamedAndDefaultThumbnailConfigsStayAllowed(): void
    {
        $rendered = $this->renderSandboxed(
            "{% set default = image.getThumbnail() %}{{ image.getThumbnail('pimcore-system-treepreview').getConfig().getName() }}",
            ['image' => new \Pimcore\Model\Asset\Image()],
        );

        $this->assertSame('pimcore-system-treepreview', $rendered);
    }

    public function testControlArrayThumbnailConfigStaysAllowedOutsideTheSandbox(): void
    {
        $config = \Pimcore\Model\Asset\Image\Thumbnail\Config::getByAutoDetect(['width' => 100]);

        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $config);
        $this->assertSame(
            [['method' => 'scaleByWidth', 'arguments' => ['width' => 100, 'forceResize' => false]]],
            array_map(
                static fn (array $item): array => ['method' => $item['method'], 'arguments' => $item['arguments']],
                $config->getItems(),
            ),
        );
    }

    public function testControlArrayThumbnailConfigWorksAgainAfterASandboxedRender(): void
    {
        $this->assertSandboxBlocks("{{ image.getThumbnail({'width': 100}).getConfig().getFormat() }}", \Twig\Sandbox\SecurityError::class, ['image' => new \Pimcore\Model\Asset\Image()]);
        $this->disableSandbox();

        $this->assertInstanceOf(
            \Pimcore\Model\Asset\Image\Thumbnail\Config::class,
            \Pimcore\Model\Asset\Image\Thumbnail\Config::getByAutoDetect(['width' => 100]),
        );
    }
}
