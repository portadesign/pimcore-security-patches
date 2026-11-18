<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-008')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class MailDocumentParamsTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\HostResidueGuard;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;

    private const KEY = 'pd-sec-mail-params';

    private const NEWSLETTER_CLASS = 'PdSecNewsletterHost';

    private const CONTROLLER = \Portadesign\PimcoreSecurityPatches\Tests\Support\MailProbeController::class . '::renderAction';

    public static function setUpBeforeClass(): void
    {
        self::removeNewsletterClass();
        $class = new \Pimcore\Model\DataObject\ClassDefinition();
        $class->setName(self::NEWSLETTER_CLASS);
        $class->setUserOwner(0);
        $class->setLayoutDefinitions((new \Pimcore\Model\DataObject\ClassDefinition\Layout\Panel())->setName('root'));
        $class->save();
    }

    public static function tearDownAfterClass(): void
    {
        self::removeNewsletterClass();
    }

    protected function setUp(): void
    {
        $this->removeDocument();
        $this->startCapturingMails();
    }

    protected function tearDown(): void
    {
        $this->stopCapturingMails();
        $this->removeDocument();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function payloadProvider(): array
    {
        return [
            'expression' => ['{{7*7}}'],
            'statement' => ['{% set a = 1 %}x'],
            'filter on empty string' => ["{{ ''|trans }}"],
            'comment' => ['{# c #}'],
            'expression after text' => ['Max {{ 7 * 191 }}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testDocumentMailDoesNotEvaluateParameters(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $mail = new \Pimcore\Mail();
        $mail->addTo('recipient@example.test');
        $mail->setDocument($document);
        $mail->setParams(['firstname' => $payload, 'lastname' => 'Smith', 'nicknames' => [$payload]]);
        $mail->send();

        $this->assertPayloadStaysLiteral($payload, $this->sentMails[0]['html'], $this->sentMails[0]['text']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testConfirmationMailDoesNotEvaluateRecipientData(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber($payload, 'Smith'), $document);

        $this->assertCount(1, $this->sentMails);
        $this->assertPayloadStaysLiteral($payload, $this->sentMails[0]['html'], $this->sentMails[0]['text']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testGetterOutputOfTheObjectParameterIsNotEvaluated(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber($payload, 'Smith'), $document, ['firstname' => 'Max']);

        $html = $this->sentMails[0]['html'];
        $this->assertStringContainsString('Hello Max', $html);
        $this->assertStringContainsString('Object ', $html);
        $this->assertPayloadStaysLiteral($payload, $html, $this->sentMails[0]['text']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testNewsletterPreparationDoesNotEvaluateRecipientData(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Newsletter::class);
        $container = new \Pimcore\Document\Newsletter\SendingParamContainer(
            'recipient@example.test',
            ['firstname' => $payload, 'lastname' => 'Smith', 'nicknames' => [$payload]],
        );

        $mail = \Pimcore\Tool\Newsletter::prepareMail($document, $container);

        $this->assertPayloadStaysLiteral($payload, (string) $mail->getHtmlBody(), (string) $mail->getTextBody());
        $this->assertStringContainsString('Editor placeholder Smith', (string) $mail->getHtmlBody());
    }

    public function testConfirmationMailKeepsTheEditorPlaceholders(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber('Max', 'Smith'), $document);

        $this->assertStringContainsString('Editor placeholder Smith', $this->sentMails[0]['html']);
        $this->assertStringContainsString('Hello Max', $this->sentMails[0]['html']);
    }

    public function testConfirmationMailKeepsFalsyStringRecipientData(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber('0', 'Smith'), $document);

        $this->assertStringContainsString('<p>Raw 0</p>', $this->sentMails[0]['html']);
    }

    public function testManuallySetBodyIsStillRenderedAsTemplate(): void
    {
        $mail = new \Pimcore\Mail();
        $mail->addTo('recipient@example.test');
        $mail->subject('s');
        $mail->html('<p>Hi {{ firstname }}</p>');
        $mail->setParams(['firstname' => 'Max']);
        $mail->send();

        $this->assertStringContainsString('<p>Hi Max</p>', $this->sentMails[0]['html']);
    }

    public function testBracesOutsideTemplateSyntaxStayAsWritten(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class, \Portadesign\PimcoreSecurityPatches\Tests\Support\MailProbeController::class . '::styledAction');

        $this->newsletter()->sendConfirmationMail($this->subscriber('a{b', 'Smith'), $document);

        $this->assertStringContainsString('<p class="pd-sec" style="color: red;">Hello a{b</p>', $this->sentMails[0]['html']);
    }

    private function assertPayloadStaysLiteral(string $payload, string $html, string $text): void
    {
        $this->assertStringNotContainsString('49', $html);
        $this->assertStringNotContainsString('1337', $html);
        $this->assertStringNotContainsString('49', $text);
        $this->assertStringNotContainsString('1337', $text);
        $this->assertStringContainsString(
            html_entity_decode(htmlspecialchars($payload), ENT_QUOTES),
            html_entity_decode($html, ENT_QUOTES),
        );
        $this->assertStringContainsString($payload, str_replace('\\', '', html_entity_decode($text, ENT_QUOTES)));
    }

    private function subscriber(string $firstname, string $lastname): \Pimcore\Model\DataObject\Concrete
    {
        return new class($firstname, $lastname) extends \Pimcore\Model\DataObject\Concrete {
            public function __construct(private readonly string $firstname, private readonly string $lastname)
            {
            }

            public function getProperties(): array
            {
                return [];
            }

            public function getFirstname(): string
            {
                return $this->firstname;
            }

            public function getLastname(): string
            {
                return $this->lastname;
            }

            public function getEmail(): string
            {
                return 'subscriber@example.test';
            }
        };
    }

    private function newsletter(): \Pimcore\Tool\Newsletter
    {
        return new \Pimcore\Tool\Newsletter(self::NEWSLETTER_CLASS);
    }

    /**
     * @param class-string<\Pimcore\Model\Document\PageSnippet> $class
     */
    private function createDocument(string $class, string $controller = self::CONTROLLER): \Pimcore\Model\Document\PageSnippet
    {
        $document = new $class();
        $document->setParentId(1);
        $document->setKey(self::KEY);
        $document->setController($controller);
        if ($document instanceof \Pimcore\Model\Document\Email) {
            $document->setSubject('pd-sec-mail-params');
        }
        $document->setEditables(['greeting' => (new \Pimcore\Model\Document\Editable\Input())->setName('greeting')->setDataFromEditmode('Editor placeholder {{ lastname }}')]);
        $document->setPublished(true);
        $document->save();

        return $document;
    }

    private function removeDocument(): void
    {
        $existing = \Pimcore\Model\Document::getByPath('/' . self::KEY);

        if ($existing instanceof \Pimcore\Model\Document) {
            $existing->delete();
        }
    }

    private static function removeNewsletterClass(): void
    {
        $class = \Pimcore\Model\DataObject\ClassDefinition::getByName(self::NEWSLETTER_CLASS);

        if ($class instanceof \Pimcore\Model\DataObject\ClassDefinition) {
            $class->delete();
        }
    }
}
