<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-005')]
final class MailAbsolutePathsDomainTest extends \PHPUnit\Framework\TestCase
{
    private const CONFIGURED_DOMAIN = 'configured.example.test';

    private const REQUEST_HOST = 'other.example.test';

    private const HTML = '<a href="/relative/page">link</a><img src="/img/logo.png">';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $originalGeneral = null;

    protected function setUp(): void
    {
        $this->originalGeneral = \Pimcore\Config::getSystemConfiguration('general');
        \Pimcore::getContainer()->get('request_stack')->push(\Symfony\Component\HttpFoundation\Request::create('http://' . self::REQUEST_HOST . '/mail'));
    }

    protected function tearDown(): void
    {
        @unlink(PIMCORE_WEB_ROOT . '/pd-sec-p3.css');
        \Pimcore::getContainer()->get('request_stack')->pop();
        \Pimcore\Config::setSystemConfiguration($this->originalGeneral, 'general');
    }

    public function testRelativePathsUseTheConfiguredDomainNotTheRequestHost(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->assertSame(
            '<a href="http://configured.example.test/relative/page">link</a><img src="http://configured.example.test/img/logo.png">',
            \Pimcore\Helper\Mail::setAbsolutePaths(self::HTML),
        );
    }

    public function testMailBodyUsesTheConfiguredDomainForRelativePaths(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);
        $mail = new \Pimcore\Mail();
        $mail->html('<p>' . self::HTML . '</p>');

        $this->assertStringContainsString(
            '<a href="http://configured.example.test/relative/page">link</a><img src="http://configured.example.test/img/logo.png">',
            (string) $mail->getBodyHtmlRendered(),
        );
    }

    public function testHostUrlIsTheRequestSchemeWithTheConfiguredDomain(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->assertSame('http://configured.example.test', \Pimcore\Helper\Mail::getHostUrl());
    }

    public function testStylesheetLookupUsesTheConfiguredDomain(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->assertSame(
            [
                'fileUrl' => 'http://configured.example.test/css/site.css',
                'fileExtension' => 'css',
                'fileUrlNormalized' => 'http://configured.example.test/css/site.css',
                'filePathNormalized' => PIMCORE_WEB_ROOT . '/css/site.css',
            ],
            \Pimcore\Helper\Mail::getNormalizedFileInfo('/css/site.css'),
        );
    }

    public function testEmbeddedStylesheetImagesUseTheConfiguredDomain(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);
        file_put_contents(PIMCORE_WEB_ROOT . '/pd-sec-p3.css', 'p { background: url(/img/bg.png); }');

        $html = \Pimcore\Helper\Mail::embedAndModifyCss('<html><head><link rel="stylesheet" href="/pd-sec-p3.css"></head><body><p>text</p></body></html>');

        $this->assertStringContainsString('<p style="background: url(http://configured.example.test/img/bg.png);">text</p>', $html);
    }

    public function testControlRelativePathsFallBackToTheRequestHostWithoutConfiguredDomain(): void
    {
        $this->configureDomain('');

        $this->assertSame(
            '<a href="http://other.example.test/relative/page">link</a><img src="http://other.example.test/img/logo.png">',
            \Pimcore\Helper\Mail::setAbsolutePaths(self::HTML),
        );
    }

    public function testHostUrlFallsBackToTheRequestHostWithoutConfiguredDomain(): void
    {
        $this->configureDomain('');

        $this->assertSame('http://other.example.test', \Pimcore\Helper\Mail::getHostUrl());
    }

    public function testControlToolHostUrlStaysTheRequestHost(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->assertSame('http://other.example.test', \Pimcore\Tool::getHostUrl());
    }

    public function testControlExplicitHostUrlWins(): void
    {
        $this->configureDomain(self::CONFIGURED_DOMAIN);

        $this->assertSame(
            '<a href="https://shop.example.test/relative/page">link</a><img src="https://shop.example.test/img/logo.png">',
            \Pimcore\Helper\Mail::setAbsolutePaths(self::HTML, null, 'https://shop.example.test'),
        );
    }

    private function configureDomain(string $domain): void
    {
        \Pimcore\Config::setSystemConfiguration(array_merge($this->originalGeneral ?? [], ['domain' => $domain]), 'general');
    }
}
