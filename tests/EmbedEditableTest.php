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
            'javascript scheme with authority' => ['javascript://example.com/%0Aalert(1)'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('maliciousUrlProvider')]
    public function testFrontendNeverOutputsMarkupFromTheStoredValue(string $url): void
    {
        $html = $this->frontend($url);

        $this->assertStringNotContainsString('<', $html);
        $this->assertStringNotContainsString('javascript:', $html);
        $this->assertStringNotContainsString('onerror=', $html);
        $this->assertStringNotContainsString('onmouseover=', $html);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('maliciousUrlProvider')]
    public function testAdminPreviewNeverOutputsMarkupFromTheStoredValue(string $url): void
    {
        $admin = $this->embed($url)->admin();

        $this->assertStringNotContainsString('<script', $admin);
        $this->assertStringNotContainsString('<img src=x', $admin);
        $this->assertStringNotContainsString('<svg', $admin);
        $this->assertStringNotContainsString('javascript:', $admin);
    }

    public function testValueStoredThroughEditmodeIsNotRenderedAsMarkup(): void
    {
        $embed = new \Pimcore\Model\Document\Editable\Embed();
        $embed->setName('pd_sec_embed');
        $embed->setDataFromEditmode(['url' => '<img src=x onerror=alert(1)>']);

        $this->assertStringNotContainsString('<img', (string) $embed->frontend());
    }

    public function testArrayUrlThroughEditmodeProducesNoOutput(): void
    {
        $embed = new \Pimcore\Model\Document\Editable\Embed();
        $embed->setName('pd_sec_embed');
        $embed->setDataFromEditmode(['url' => ['https://example.com']]);

        $this->assertSame('', (string) $embed->frontend());
    }

    public function testArrayUrlFromResourceProducesNoOutput(): void
    {
        $this->assertSame('', (string) $this->embedRaw(['url' => ['https://example.com']])->frontend());
    }

    public function testUppercaseSchemeIsOutputAsUrl(): void
    {
        $this->assertSame('HTTPS://EXAMPLE.COM', $this->frontend('HTTPS://EXAMPLE.COM'));
    }

    public function testSurroundingWhitespaceIsTrimmed(): void
    {
        $this->assertSame('https://example.com', $this->frontend(' https://example.com '));
    }

    public function testPlainUrlIsOutputEscaped(): void
    {
        $html = $this->frontend('https://example.com/page?a=1&b=2');

        $this->assertSame('https://example.com/page?a=1&amp;b=2', $html);
    }

    public function testProviderUrlStillEmbedsWithoutNetworkAccess(): void
    {
        $embed = $this->embed('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
        $embed->setConfig(['fake_responses' => \Embera\Embera::ONLY_FAKE_RESPONSES]);

        $html = (string) $embed->frontend();

        $this->assertStringContainsString('<iframe', $html);
        $this->assertStringContainsString('youtube.com/embed/dQw4w9WgXcQ', $html);
    }

    private function frontend(string $url): string
    {
        return (string) $this->embed($url)->frontend();
    }

    private function embed(string $url): \Pimcore\Model\Document\Editable\Embed
    {
        return $this->embedRaw(['url' => $url]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function embedRaw(array $data): \Pimcore\Model\Document\Editable\Embed
    {
        $embed = new \Pimcore\Model\Document\Editable\Embed();
        $embed->setName('pd_sec_embed');
        $embed->setDataFromResource(serialize($data));

        return $embed;
    }
}
