<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
final class NotificationMailRenderingTest extends \PHPUnit\Framework\TestCase
{
    private const RECIPIENT = 'pd-sec-notification-user';

    private const ELEMENT_ID = 990017;

    private const TEMPLATE_NAME = 'pd-sec-p3-notification.html.twig';

    private const DOMAIN = 'configured.example.test';

    private ?\Closure $mailListener = null;

    /**
     * @var array<string, mixed>|null
     */
    private ?array $originalGeneral = null;

    private int $highestLogIdBefore = 0;

    private int $highestNoteIdBefore = 0;

    /**
     * @var list<string>
     */
    private array $sentHtml = [];

    /**
     * @var list<string>
     */
    private array $sentText = [];

    /**
     * @var list<string>
     */
    private array $sentSubjects = [];

    protected function setUp(): void
    {
        $db = \Pimcore\Db::get();
        $this->highestLogIdBefore = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM email_log');
        $this->highestNoteIdBefore = (int) $db->fetchOne('SELECT COALESCE(MAX(id), 0) FROM notes');

        \Pimcore\Model\User::getByName(self::RECIPIENT)?->delete();
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::RECIPIENT,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $user->setEmail('pd-sec-notification@example.test');
        $user->save();

        $this->originalGeneral = \Pimcore\Config::getSystemConfiguration('general');
        \Pimcore\Config::setSystemConfiguration(array_merge($this->originalGeneral ?? [], ['domain' => self::DOMAIN]), 'general');

        $this->sentHtml = [];
        $this->sentText = [];
        $this->sentSubjects = [];
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->sentHtml[] = (string) $mail->getHtmlBody();
            $this->sentText[] = (string) $mail->getTextBody();
            $this->sentSubjects[] = (string) $mail->getSubject();
            $mail->disableLogging();
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);
    }

    protected function tearDown(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
        }

        \Pimcore\Config::setSystemConfiguration($this->originalGeneral, 'general');
        @unlink($this->templateFile());
        $db = \Pimcore\Db::get();
        $db->executeStatement('DELETE FROM notes WHERE id > ?', [$this->highestNoteIdBefore]);
        foreach ($db->fetchFirstColumn('SELECT id FROM email_log WHERE id > ?', [$this->highestLogIdBefore]) as $id) {
            \Pimcore\Model\Tool\Email\Log::getById((int) $id)?->delete();
        }
        \Pimcore\Model\User::getByName(self::RECIPIENT)?->delete();
    }

    public function testWorkflowNotificationKeepsNoteTextLiteral(): void
    {
        $this->createNote('pd2026002-note-{{7*7}}-end');

        $this->notify('notified');

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString('<p>pd2026002-note-{{7*7}}-end</p>', $this->sentHtml[0]);
    }

    public function testWorkflowNotificationIsSentAsBuiltWithAbsolutePathsInlineCssAndPlainText(): void
    {
        file_put_contents($this->templateFile(), <<<'TWIG'
<html><head><style>p { color: red; }</style></head><body><p>{{ subject.getKey() }}|{{ note_description }}</p><a href="/relative/page">link</a><img src="/img/logo.png"></body></html>
TWIG);
        $this->createNote('pd2026002-note-{{7*7}}');

        $this->notify('notified-{{7*7}}', self::TEMPLATE_NAME);

        $this->assertSame(
            [
                'subjects' => ["Workflow update for object /notified-{{7*7}} in workflow 'pd-sec-workflow'"],
                'html' => [
                    "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" \"http://www.w3.org/TR/REC-html40/loose.dtd\">\n"
                    . "<html>\n"
                    . "<head><style>p { color: red; }</style></head>\n"
                    . "<body>\n"
                    . "<p style=\"color: red;\">notified-{{7*7}}|pd2026002-note-{{7*7}}</p>\n"
                    . "<a href=\"http://configured.example.test/relative/page\">link</a><img src=\"http://configured.example.test/img/logo.png\">\n"
                    . "</body>\n"
                    . "</html>",
                ],
            ],
            ['subjects' => $this->sentSubjects, 'html' => $this->sentHtml],
        );
        $this->assertCount(1, $this->sentText);
        $this->assertStringContainsString('notified-{{7\*7}}|pd2026002-note-{{7\*7}}', $this->sentText[0]);
        $this->assertStringContainsString('[link](http://configured.example.test/relative/page)', $this->sentText[0]);
    }

    public function testWorkflowDeeplinkUsesTheConfiguredDomainNotTheRequestHost(): void
    {
        \Pimcore::getContainer()->get('request_stack')->push(\Symfony\Component\HttpFoundation\Request::create('http://other.example.test/admin'));

        try {
            $this->notify('notified');
        } finally {
            \Pimcore::getContainer()->get('request_stack')->pop();
        }

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString('<a href="http://configured.example.test/admin/login/deeplink?object_990017_object" target="_blank">', $this->sentHtml[0]);
    }

    public function testControlWorkflowNotificationDeliversPlainNoteText(): void
    {
        $this->createNote('pd2026002-plain-note');

        $this->notify('notified');

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString('<p>pd2026002-plain-note</p>', $this->sentHtml[0]);
    }

    private function templateFile(): string
    {
        return PIMCORE_PROJECT_ROOT . '/templates/' . self::TEMPLATE_NAME;
    }

    private function createNote(string $description): void
    {
        $note = new \Pimcore\Model\Element\Note();
        $note->setCid(self::ELEMENT_ID);
        $note->setCtype('object');
        $note->setDate(time());
        $note->setTitle('pd-sec-note');
        $note->setType('content');
        $note->setDescription($description);
        $note->save();
    }

    private function notify(string $key, string $template = '@PimcoreCore/Workflow/NotificationEmail/notificationEmail.html.twig'): void
    {
        $container = \Pimcore::getContainer();
        $service = new \Pimcore\Workflow\Notification\NotificationEmailService(
            $container->get('pimcore.templating.engine.delegating'),
            $container->get('router'),
            $container->get('translator'),
        );
        $element = new \Pimcore\Model\DataObject\Folder();
        $element->setId(self::ELEMENT_ID);
        $element->setKey($key);
        $element->setParentId(1);
        $element->setPath('/');
        $workflow = new \Symfony\Component\Workflow\Workflow(new \Symfony\Component\Workflow\Definition([], []), name: 'pd-sec-workflow');

        $service->sendWorkflowEmailNotification(
            [self::RECIPIENT],
            [],
            $workflow,
            'object',
            $element,
            'publish',
            \Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_TEMPLATE,
            $template,
        );
    }
}
