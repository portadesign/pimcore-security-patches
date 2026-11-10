<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-5362')]
final class EmbedEditableTest extends \PHPUnit\Framework\TestCase
{
    protected function setUp(): void
    {
        \Pimcore\Cache::clearTag('embed');
    }

    protected function tearDown(): void
    {
        \Pimcore\Cache::clearTag('embed');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function maliciousUrlProvider(): array
    {
        return [
            'image with handler' => ['<img src=x onerror=alert(1)>'],
            'script tag' => ['<script>alert(1)</script>'],
            'script before a provider url' => ['<script>alert(1)</script> https://www.youtube.com/watch?v=dQw4w9WgXcQ'],
            'attribute breakout' => ['https://example.com/"onmouseover="alert(1)'],
            'single quote breakout' => ["https://example.com/'onmouseover='alert(1)"],
            'tag after a url' => ['https://example.com/ <svg onload=alert(1)>'],
            'javascript scheme' => ['javascript:alert(1)'],
            'data scheme' => ['data:text/html,<script>alert(1)</script>'],
            'angle brackets inside the url' => ['https://example.com/<script>alert(1)</script>'],
            'whitespace separated payload' => ["https://example.com/\n<img src=x onerror=alert(1)>"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('maliciousUrlProvider')]
    public function testFrontendNeverOutputsMarkupFromTheStoredValue(string $url): void
    {
        $html = $this->frontend($url);

        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringNotContainsString('<svg', $html);
        $this->assertStringNotContainsString('onmouseover=', $html);
        $this->assertStringNotContainsString('javascript:', $html);
        $this->assertSame('', $html);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('maliciousUrlProvider')]
    public function testAdminPreviewNeverOutputsMarkupFromTheStoredValue(string $url): void
    {
        $embed = $this->embed($url);

        $this->assertStringNotContainsString('<script', $embed->admin());
        $this->assertStringNotContainsString('<img src=x', $embed->admin());
        $this->assertStringNotContainsString('<svg', $embed->admin());
    }

    public function testValueStoredThroughEditmodeIsNotRenderedAsMarkup(): void
    {
        $embed = new \Pimcore\Model\Document\Editable\Embed();
        $embed->setName('pd_sec_embed');
        $embed->setDataFromEditmode(['url' => '<img src=x onerror=alert(1)>']);

        $this->assertSame('', $embed->frontend());
    }

    public function testPlainUrlIsOutputEscaped(): void
    {
        $html = $this->frontend('https://example.com/page?a=1&b=2');

        $this->assertSame('https://example.com/page?a=1&amp;b=2', $html);
    }

    public function testEmptyUrlProducesNoOutput(): void
    {
        $this->assertSame('', $this->frontend(''));
    }

    private function frontend(string $url): string
    {
        return (string) $this->embed($url)->frontend();
    }

    private function embed(string $url): \Pimcore\Model\Document\Editable\Embed
    {
        $embed = new \Pimcore\Model\Document\Editable\Embed();
        $embed->setName('pd_sec_embed');
        $embed->setDataFromResource(serialize(['url' => $url]));

        return $embed;
    }
}
