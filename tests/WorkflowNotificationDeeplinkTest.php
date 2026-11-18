<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115898')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class WorkflowNotificationDeeplinkTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\HostResidueGuard;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;

    private const USERNAME = 'pd-sec-workflow-notified-user';

    private const DOMAIN = 'configured.example.test';

    private const ELEMENT_ID = 990019;

    private const TEMPLATE = '@PimcoreCore/Workflow/NotificationEmail/notificationEmail.html.twig';

    private const DOCUMENT_KEY = 'pd-sec-workflow-mail';

    private string $originalBaseUrl = '';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $originalGeneral = null;

    protected function setUp(): void
    {
        $this->originalBaseUrl = $this->routerContext()->getBaseUrl();
        $this->originalGeneral = \Pimcore\Config::getSystemConfiguration('general');
        \Pimcore\Config::setSystemConfiguration(array_merge($this->originalGeneral ?? [], ['domain' => self::DOMAIN]), 'general');

        \Pimcore\Model\User::getByName(self::USERNAME)?->delete();
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
        ]);
        $user->setEmail('workflow-recipient@example.test');
        $user->save();

        $this->removeDocument();
        $document = new \Pimcore\Model\Document\Email();
        $document->setParentId(1);
        $document->setKey(self::DOCUMENT_KEY);
        $document->setController(\Portadesign\PimcoreSecurityPatches\Tests\Support\DeeplinkProbeController::class . '::renderAction');
        $document->setSubject('pd-sec-workflow-mail');
        $document->setPublished(true);
        $document->save();

        $this->startCapturingMails();
    }

    protected function tearDown(): void
    {
        $this->stopCapturingMails();
        $this->routerContext()->setBaseUrl($this->originalBaseUrl);
        $this->removeDocument();
        \Pimcore\Config::setSystemConfiguration($this->originalGeneral, 'general');
        \Pimcore\Model\User::getByName(self::USERNAME)?->delete();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function baseUrlProvider(): array
    {
        return [
            'path prefix with expression' => ['/proxy{{7*7}}', '/proxy%7B%7B7%2A7%7D%7D'],
            'path prefix with statement' => ['/{% set a = 1 %}x', '/%7B%25%20set%20a%20%3D%201%20%25%7Dx'],
            'path prefix with comment' => ['/{# c #}', '/%7B%23%20c%20%23%7D'],
            'path prefix with filter on empty string' => ["/{{ ''|trans }}", '/%7B%7B%20%27%27%7Ctrans%20%7D%7D'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('baseUrlProvider')]
    public function testDeeplinkDoesNotCarryTemplateSyntaxFromTheRequestBaseUrl(string $baseUrl, string $expectedBaseUrl): void
    {
        $this->routerContext()->setBaseUrl($baseUrl);

        $this->notify();

        $this->assertDeeplinkIsMailed($expectedBaseUrl);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('baseUrlProvider')]
    public function testDocumentMailDeeplinkDoesNotCarryTemplateSyntaxFromTheRequestBaseUrl(string $baseUrl, string $expectedBaseUrl): void
    {
        $this->routerContext()->setBaseUrl($baseUrl);

        $this->notify(\Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_DOCUMENT);

        $this->assertDeeplinkIsMailed($expectedBaseUrl);
    }

    public function testControlDocumentMailKeepsAPlainBaseUrl(): void
    {
        $this->routerContext()->setBaseUrl('/pim');

        $this->notify(\Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_DOCUMENT);

        $this->assertDeeplinkIsMailed('/pim');
    }

    public function testControlPlainBaseUrlIsKeptInTheDeeplink(): void
    {
        $this->routerContext()->setBaseUrl('/pim');

        $this->notify();

        $this->assertDeeplinkIsMailed('/pim');
    }

    public function testControlWithoutBaseUrlTheDeeplinkIsTheAdminDeeplinkRoute(): void
    {
        $this->routerContext()->setBaseUrl('');

        $this->notify();

        $this->assertDeeplinkIsMailed('');
    }

    private function assertDeeplinkIsMailed(string $expectedBaseUrl): void
    {
        $this->assertCount(1, $this->sentMails, 'exactly one notification mail must be sent');
        $this->assertSame(['workflow-recipient@example.test'], $this->sentMails[0]['recipients']);

        $expectedLink = 'http://' . self::DOMAIN . $expectedBaseUrl . '/admin/login/deeplink?object_' . self::ELEMENT_ID . '_object';
        $this->assertStringContainsString('<a href="' . $expectedLink . '"', $this->sentMails[0]['html']);
    }

    private function notify(string $mailType = \Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_TEMPLATE): void
    {
        $container = \Pimcore::getContainer();
        $service = new \Pimcore\Workflow\Notification\NotificationEmailService(
            $container->get('pimcore.templating.engine.delegating'),
            $container->get('router'),
            $container->get('translator'),
        );

        $element = new \Pimcore\Model\DataObject\Folder();
        $element->setId(self::ELEMENT_ID);
        $element->setKey('pd-sec-workflow');
        $element->setParentId(1);
        $element->setPath('/');

        $service->sendWorkflowEmailNotification(
            [self::USERNAME],
            [],
            new \Symfony\Component\Workflow\Workflow(new \Symfony\Component\Workflow\Definition([], []), name: 'pd-sec-workflow'),
            'object',
            $element,
            'publish',
            $mailType,
            \Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_DOCUMENT === $mailType ? '/' . self::DOCUMENT_KEY : self::TEMPLATE,
        );
    }

    private function removeDocument(): void
    {
        $existing = \Pimcore\Model\Document::getByPath('/' . self::DOCUMENT_KEY);

        if ($existing instanceof \Pimcore\Model\Document) {
            $existing->delete();
        }
    }

    private function routerContext(): \Symfony\Component\Routing\RequestContext
    {
        $router = \Pimcore::getContainer()->get('router');
        \assert($router instanceof \Symfony\Component\Routing\RouterInterface);

        return $router->getContext();
    }
}
