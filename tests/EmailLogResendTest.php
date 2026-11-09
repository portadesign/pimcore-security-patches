<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
final class EmailLogResendTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-emaillog-user';

    private const RESTRICTED_USERNAME = 'pd-sec-emaillog-restricted-user';

    private const PLAIN = 'plain body';

    private int $highestLogIdBefore = 0;

    private ?\Pimcore\Model\Tool\Email\Log $log = null;

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $restrictedUser;

    /**
     * @var list<array{html: string, text: string, subject: string}>
     */
    private array $sentMails = [];

    private ?\Closure $mailListener = null;

    private bool $keepLogging = false;

    protected function setUp(): void
    {
        $this->highestLogIdBefore = (int) \Pimcore\Db::get()->fetchOne('SELECT COALESCE(MAX(id), 0) FROM email_log');

        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
        $this->user = $this->createUser(self::USERNAME, ['emails']);
        $this->restrictedUser = $this->createUser(self::RESTRICTED_USERNAME, []);
        $this->authenticate($this->user);

        $this->sentMails = [];
        $this->keepLogging = false;
        $this->mailListener = function (\Pimcore\Event\Model\MailEvent $event): void {
            $mail = $event->getMail();
            $this->sentMails[] = [
                'html' => (string) $mail->getHtmlBody(),
                'text' => (string) $mail->getTextBody(),
                'subject' => (string) $mail->getSubject(),
            ];
            if (!$this->keepLogging) {
                $mail->disableLogging();
            }
            $event->setArguments([]);
        };
        \Pimcore::getEventDispatcher()->addListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener, 1000);
    }

    protected function tearDown(): void
    {
        if (null !== $this->mailListener) {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Event\MailEvents::PRE_SEND, $this->mailListener);
        }

        $this->authenticate(null);
        $this->log = null;
        foreach ($this->createdLogIds(includeFixture: true) as $id) {
            \Pimcore\Model\Tool\Email\Log::getById($id)?->delete();
        }
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function templatePayloadProvider(): array
    {
        return [
            'expression only' => ['pd2026002-resend-{{7*7}}-end'],
            'expression and statement' => ['pd2026002-resend-{{7*7}} {% if 1 %}x{% endif %}-end'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('templatePayloadProvider')]
    public function testResendKeepsTemplateSyntaxOfTheLoggedBodiesLiteral(string $payload): void
    {
        $log = $this->createLog($payload);

        $response = $this->resend(['id' => $log->getId()]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            [['html' => $payload, 'text' => $payload, 'subject' => $payload]],
            $this->sentMails,
        );
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('templatePayloadProvider')]
    public function testResendToNewRecipientLogsTheOriginalBodiesAndSubject(string $payload): void
    {
        $log = $this->createLog($payload);
        $this->keepLogging = true;

        $response = $this->resend(['id' => $log->getId(), 'to' => 'new-recipient@example.test']);

        $this->assertSame(200, $response->getStatusCode());
        $newIds = $this->createdLogIds();
        $this->assertCount(1, $newIds, 'exactly one new log row');
        $newLog = \Pimcore\Model\Tool\Email\Log::getById($newIds[0]);
        $this->assertInstanceOf(\Pimcore\Model\Tool\Email\Log::class, $newLog);
        $this->assertSame(
            ['subject' => $payload, 'html' => $payload, 'text' => $payload],
            ['subject' => $newLog->getSubject(), 'html' => $newLog->getHtmlLog(), 'text' => $newLog->getTextLog()],
        );
    }

    public function testControlResendWithoutRecipientOverrideWritesNoNewLogEntry(): void
    {
        $log = $this->createLog(self::PLAIN);
        $this->keepLogging = true;

        $this->resend(['id' => $log->getId()]);

        $this->assertCount(1, $this->sentMails);
        $this->assertSame([$log->getId()], $this->createdLogIds(includeFixture: true));
    }

    public function testControlUserWithoutEmailsPermissionIsDenied(): void
    {
        $log = $this->createLog(self::PLAIN);
        $this->authenticate($this->restrictedUser);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->resend(['id' => $log->getId()]);
    }

    private function createLog(string $payload): \Pimcore\Model\Tool\Email\Log
    {
        $log = new \Pimcore\Model\Tool\Email\Log();
        $log->setSubject($payload);
        $log->setSentDate(time());
        $log->setFrom('sender@example.test');
        $log->setTo('original-recipient@example.test');
        $log->setParams([]);
        $log->setBodyHtml($payload);
        $log->setBodyText($payload);
        $log->save();
        $this->log = $log;

        return $log;
    }

    /**
     * @param array<string, int|string|null> $parameters
     */
    private function resend(array $parameters): \Symfony\Component\HttpFoundation\Response
    {
        return $this->controller()->resendEmailAction(\Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/email/resend-email',
            method: 'POST',
            parameters: $parameters,
        ));
    }

    /**
     * @return list<int>
     */
    private function createdLogIds(bool $includeFixture = false): array
    {
        $ids = array_map(
            'intval',
            \Pimcore\Db::get()->fetchFirstColumn('SELECT id FROM email_log WHERE id > ? ORDER BY id', [$this->highestLogIdBefore]),
        );

        return $includeFixture || null === $this->log ? $ids : array_values(array_diff($ids, [$this->log->getId()]));
    }

    /**
     * @param list<string> $permissions
     */
    private function createUser(string $name, array $permissions): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $user->setPermissions($permissions);
        $user->save();

        return $user;
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Admin\EmailController
    {
        $container = \Pimcore::getContainer();

        if ($container->has(\Pimcore\Bundle\AdminBundle\Controller\Admin\EmailController::class)) {
            return $container->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\EmailController::class);
        }

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\EmailController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }
}
