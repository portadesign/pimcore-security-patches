<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxCallerTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    protected function tearDown(): void
    {
        $this->disableSandbox();
    }

    public function testTextLayoutRefusesToMutateTheObject(): void
    {
        $object = new \Pimcore\Model\DataObject\Folder();
        $object->setKey('original');
        $layout = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Text();
        $layout->setHtml("{% set changed = object.setKey('mutated') %}key:{{ object.getKey() }}");

        $html = $layout->enrichLayoutDefinition($object, [])->getHtml();

        $this->assertSame(
            ['original', 'Calling method "setKey" on "Pimcore\Model\DataObject\Folder" is not allowed in templates'],
            [$object->getKey(), $this->layoutErrorDetail($html)],
        );
    }

    public function testControlTextLayoutRendersHarmlessTemplate(): void
    {
        $object = new \Pimcore\Model\DataObject\Folder();
        $object->setKey('original');
        $layout = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Text();
        $layout->setHtml('<p>{{ object.getKey() }}</p>');

        $this->assertSame('<p>original</p>', $layout->enrichLayoutDefinition($object, [])->getHtml());
    }

    public function testMailSubjectDoesNotRevealTheUserPassword(): void
    {
        $mail = $this->mailWithUser();
        $mail->subject('Reset {{ user.getPassword() }}');

        $this->assertSame($this->expectedMailError('subject'), $this->renderingFailure(static fn (): string => $mail->getSubjectRendered()));
    }

    public function testMailHtmlBodyDoesNotRevealTheUserPassword(): void
    {
        $mail = $this->mailWithUser();
        $mail->html('<p>{{ user.getPassword() }}</p>');

        $this->assertSame($this->expectedMailError('body'), $this->renderingFailure(static fn (): ?string => $mail->getBodyHtmlRendered()));
    }

    public function testMailTextBodyDoesNotRevealTheUserPassword(): void
    {
        $mail = $this->mailWithUser();
        $mail->text('{{ user.getPassword() }}');

        $this->assertSame($this->expectedMailError('body'), $this->renderingFailure(static fn (): string => $mail->getBodyTextRendered()));
    }

    public function testControlMailRendersHarmlessParameters(): void
    {
        $mail = $this->mailWithUser();
        $mail->subject('Hello {{ name }}');
        $mail->text('Dear {{ name }}');
        $mail->setParam('name', 'Alice');

        $this->assertSame(
            ['Hello Alice', 'Dear Alice'],
            [$this->renderingFailure(static fn (): string => $mail->getSubjectRendered()), $mail->getBodyTextRendered()],
        );
    }

    public function testWeb2PrintHtmlDoesNotRevealTheUserPassword(): void
    {
        $processor = new class () extends \Pimcore\Web2Print\Processor {
            protected function buildPdf(\Pimcore\Model\Document\PrintAbstract $document, $config)
            {
                return '';
            }

            public function getProcessingOptions()
            {
                return [];
            }

            public function getPdfFromString($html, $params = [], $returnFilePath = false)
            {
                return '';
            }
        };
        $user = new \Pimcore\Model\User();
        $user->setPassword('hash-123');
        $method = new \ReflectionMethod($processor, 'processHtml');

        $outcome = $this->renderingFailure(static fn (): string => $method->invoke($processor, '<p>{{ user.getPassword() }}</p>', ['user' => $user]));

        $this->assertSame(
            'Failed rendering the print template: Calling method "getPassword" on "Pimcore\Model\User" is not allowed in templates in "__string_template__" at line 1.. Please check your twig sandbox security policy or contact the administrator.',
            preg_replace('/__string_template__[0-9a-f]+/', '__string_template__', $outcome),
        );
    }

    public function testControlWeb2PrintRendersHarmlessParameters(): void
    {
        $processor = new class () extends \Pimcore\Web2Print\Processor {
            protected function buildPdf(\Pimcore\Model\Document\PrintAbstract $document, $config)
            {
                return '';
            }

            public function getProcessingOptions()
            {
                return [];
            }

            public function getPdfFromString($html, $params = [], $returnFilePath = false)
            {
                return '';
            }
        };
        $method = new \ReflectionMethod($processor, 'processHtml');

        $this->assertSame('<p>Hello</p>', $method->invoke($processor, '<p>{{ greeting }}</p>', ['greeting' => 'Hello']));
    }

    private function mailWithUser(): \Pimcore\Mail
    {
        $user = new \Pimcore\Model\User();
        $user->setName('sender');
        $user->setPassword('hash-123');

        $mail = new \Pimcore\Mail();
        $mail->setParam('user', $user);

        return $mail;
    }

    private function expectedMailError(string $context): string
    {
        return sprintf(
            'Failed rendering the %s: Calling method "getPassword" on "Pimcore\Model\User" is not allowed in templates. Please check your twig sandbox security policy or contact the administrator.',
            $context,
        );
    }

    private function renderingFailure(\Closure $render): string
    {
        try {
            return (string) $render();
        } catch (\Exception $exception) {
            return $exception->getMessage();
        }
    }

    private function layoutErrorDetail(string $html): string
    {
        $this->assertSame(1, preg_match('/^<h2>Error<\/h2>Failed rendering the template: <b>(.*)<\/b>\.\s+Please check your twig sandbox security policy or contact the administrator\.$/s', $html, $matches), 'unexpected layout output: ' . $html);

        return $matches[1];
    }
}
