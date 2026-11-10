<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-008')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class MailDocumentParamsTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;

    private const KEY = 'pd-sec-mail-params';

    private const CONTROLLER = \Portadesign\PimcoreSecurityPatches\Tests\Support\MailProbeController::class . '::renderAction';

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
    public function testConfirmationMailDoesNotEvaluateRecipientData(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber($payload, 'Smith'), $document);

        $this->assertCount(1, $this->sentMails);
        $this->assertPayloadStaysLiteral($payload, $this->sentMails[0]['html'], $this->sentMails[0]['text']);
    }

    public function testConfirmationMailKeepsTheEditorPlaceholders(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber('Max', 'Smith'), $document);

        $this->assertStringContainsString('Editor placeholder Smith', $this->sentMails[0]['html']);
        $this->assertStringContainsString('Hello Max', $this->sentMails[0]['html']);
        $this->assertStringContainsString('Editor placeholder Smith', $this->sentMails[0]['text']);
    }

    public function testConfirmationMailKeepsSpecialCharactersOfRecipientData(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber('Zoë & <b>Co</b>', 'O\'Neil'), $document);

        $html = $this->sentMails[0]['html'];
        $this->assertStringContainsString('Hello Zoë &amp; &lt;b&gt;Co&lt;/b&gt;', $html);
        $this->assertStringContainsString("Editor placeholder O'Neil", html_entity_decode($html, ENT_QUOTES));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('payloadProvider')]
    public function testNewsletterPreparationDoesNotEvaluateRecipientData(string $payload): void
    {
        $document = $this->createDocument(\Pimcore\Bundle\NewsletterBundle\Model\Document\Newsletter::class);
        $container = new \Pimcore\Bundle\NewsletterBundle\Document\Newsletter\SendingParamContainer(
            'recipient@example.test',
            ['firstname' => $payload, 'lastname' => 'Smith', 'nicknames' => [$payload]],
        );

        $mail = \Pimcore\Bundle\NewsletterBundle\Tool\Newsletter::prepareMail($document, $container);

        $this->assertPayloadStaysLiteral($payload, (string) $mail->getHtmlBody(), (string) $mail->getTextBody());
        $this->assertStringContainsString('Editor placeholder Smith', (string) $mail->getHtmlBody());
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

    public function testRecipientDataInUrlsIsEncodedByTheTemplate(): void
    {
        $document = $this->createDocument(\Pimcore\Model\Document\Email::class);

        $this->newsletter()->sendConfirmationMail($this->subscriber('a{b', 'Smith'), $document);

        $this->assertStringContainsString('?n=a%7Bb"', $this->sentMails[0]['html']);
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

    private function newsletter(): \Pimcore\Bundle\NewsletterBundle\Tool\Newsletter
    {
        return new \Pimcore\Bundle\NewsletterBundle\Tool\Newsletter('brand');
    }

    /**
     * @param class-string<\Pimcore\Model\Document\Email> $class
     */
    private function createDocument(string $class): \Pimcore\Model\Document\Email
    {
        $document = new $class();
        $document->setParentId(1);
        $document->setKey(self::KEY);
        $document->setController(self::CONTROLLER);
        $document->setSubject('pd-sec-mail-params');
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
}
