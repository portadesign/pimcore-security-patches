<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxCsrfTokenTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    private const TOKEN = 'pd-sec-csrf-token-0123456789abcdef';

    protected function setUp(): void
    {
        $this->setTwigGlobal('csrfToken', self::TOKEN);
    }

    protected function tearDown(): void
    {
        $this->disableSandbox();
        $this->removeTwigGlobal('csrfToken');
    }

    public function testControlGlobalIsVisibleToTemplatesWithoutSandbox(): void
    {
        $twig = $this->sandboxEngine()->getTwigEnvironment();

        $this->assertSame(self::TOKEN, $twig->createTemplate('{{ csrfToken }}')->render([]));
    }

    public function testMailSubjectDoesNotRevealTheCsrfToken(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->subject('[{{ csrfToken }}]');

        $this->assertSame('[]', $mail->getSubjectRendered());
    }

    public function testMailHtmlBodyDoesNotRevealTheCsrfToken(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->html('<p>[{{ csrfToken }}]</p>');

        $this->assertSame('<p>[]</p>', preg_replace('#^.*<body>|</body>.*$#s', '', (string) $mail->getBodyHtmlRendered()));
    }

    public function testMailTextBodyDoesNotRevealTheCsrfToken(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->text('[{{ csrfToken }}]');

        $this->assertSame('[]', $mail->getBodyTextRendered());
    }

    public function testTextLayoutDoesNotRevealTheCsrfToken(): void
    {
        $layout = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Text();
        $layout->setHtml('<p>[{{ csrfToken }}]</p>');

        $this->assertSame('<p>[]</p>', $layout->enrichLayoutDefinition(new \Pimcore\Model\DataObject\Folder(), [])->getHtml());
    }

    public function testPrintTemplateDoesNotRevealTheCsrfToken(): void
    {
        $this->assertSame('<p>[]</p>', (new \Portadesign\PimcoreSecurityPatches\Tests\Support\StubPrintProcessor())->renderHtml('<p>[{{ csrfToken }}]</p>'));
    }

    public function testRenderParametersStillReachSandboxedTemplatesWithoutTheCsrfToken(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->subject('Hello {{ name }} [{{ csrfToken }}]');
        $mail->setParam('name', 'Alice');

        $layout = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Text();
        $layout->setHtml('{{ object.getKey() }}');
        $object = new \Pimcore\Model\DataObject\Folder();
        $object->setKey('folder');

        $this->assertSame(
            ['Hello Alice []', 'folder', '<p>Hello</p>'],
            [
                $mail->getSubjectRendered(),
                $layout->enrichLayoutDefinition($object, [])->getHtml(),
                (new \Portadesign\PimcoreSecurityPatches\Tests\Support\StubPrintProcessor())->renderHtml('<p>{{ greeting }}</p>', ['greeting' => 'Hello']),
            ],
        );
    }
}
