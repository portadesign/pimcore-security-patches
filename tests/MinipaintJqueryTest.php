<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('GHSA-jmh9-6rjq-gjh9')]
final class MinipaintJqueryTest extends \PHPUnit\Framework\TestCase
{
    private const BUNDLE = '/vendor/pimcore/pimcore/bundles/AdminBundle/Resources/public/js/lib/minipaint/dist/bundle.js';

    private string $node;

    protected function setUp(): void
    {
        $node = (new \Symfony\Component\Process\ExecutableFinder())->find('node');
        if (null === $node) {
            $this->markTestSkipped('node is not installed on this host; run tests/js/minipaint-jquery-probe.cjs <bundle.js> --check on a host with node');
        }
        $this->node = $node;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mutationPayloadProvider(): array
    {
        return [
            'style with self-closing style, spaced' => ['<style><style /><img src=x onerror=alert(1)>'],
            'style with self-closing style, compact' => ['<style><style/><img src=x onerror=_=1>'],
            'wrapped in div' => ['<div><style><style /><img src=x onerror=alert(1)></style></div>'],
            'plain self-closing element' => ['<span/>'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('mutationPayloadProvider')]
    public function testHtmlPrefilterKeepsMarkupUnchanged(string $html): void
    {
        $this->assertSame($html, $this->prefilter($html)['output']);
    }

    public function testControlMarkupWithoutSelfClosingTagsIsUnchanged(): void
    {
        $html = '<div class="a"><b>text</b></div>';

        $this->assertSame($html, $this->prefilter($html)['output']);
    }

    public function testBundleStillExportsJquery341(): void
    {
        $this->assertSame('3.4.1', $this->prefilter('<b></b>')['jquery']);
    }

    /**
     * @return array{jquery: string, output: string}
     */
    private function prefilter(string $html): array
    {
        $process = new \Symfony\Component\Process\Process(
            command: [
                $this->node,
                __DIR__ . '/js/minipaint-jquery-probe.cjs',
                PIMCORE_PROJECT_ROOT . self::BUNDLE,
                json_encode([$html], JSON_THROW_ON_ERROR),
            ],
            timeout: 30,
        );
        $process->mustRun();

        /** @var array{jquery: string, outputs: list<string>} $result */
        $result = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);

        return ['jquery' => $result['jquery'], 'output' => $result['outputs'][0]];
    }
}
