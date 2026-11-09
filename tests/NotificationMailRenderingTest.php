<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
final class NotificationMailRenderingTest extends \PHPUnit\Framework\TestCase
{
    private const RECIPIENT = 'pd-sec-notification-user';

    private const ELEMENT_ID = 990017;

    private ?\Closure $mailListener = null;

    private int $highestLogIdBefore = 0;

    private int $highestNoteIdBefore = 0;

    /**
     * @var list<string>
     */
    private array $sentHtml = [];

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

        $this->sentHtml = [];
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->sentHtml[] = (string) $mail->getHtmlBody();
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

        $this->notify();

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString('pd2026002-note-{{7*7}}-end', $this->sentHtml[0]);
        $this->assertStringNotContainsString('pd2026002-note-49-end', $this->sentHtml[0]);
    }

    public function testControlWorkflowNotificationDeliversPlainNoteText(): void
    {
        $this->createNote('pd2026002-plain-note');

        $this->notify();

        $this->assertCount(1, $this->sentHtml);
        $this->assertStringContainsString('<p>pd2026002-plain-note</p>', $this->sentHtml[0]);
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

    private function notify(): void
    {
        $container = \Pimcore::getContainer();
        $service = new \Pimcore\Workflow\Notification\NotificationEmailService(
            $container->get('pimcore.templating.engine.delegating'),
            $container->get('router'),
            $container->get('translator'),
        );
        $element = new \Pimcore\Model\DataObject\Folder();
        $element->setId(self::ELEMENT_ID);
        $element->setKey('notified');
        $element->setParentId(1);
        $workflow = new \Symfony\Component\Workflow\Workflow(new \Symfony\Component\Workflow\Definition([], []), name: 'pd-sec-workflow');

        $service->sendWorkflowEmailNotification(
            [self::RECIPIENT],
            [],
            $workflow,
            'object',
            $element,
            'publish',
            \Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_TEMPLATE,
            '@PimcoreCore/Workflow/NotificationEmail/notificationEmail.html.twig',
        );
    }
}
