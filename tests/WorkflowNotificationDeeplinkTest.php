<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115898')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class WorkflowNotificationDeeplinkTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MainDomainFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;

    private const USERNAME = 'pd-sec-workflow-notified-user';

    private const FOLDER = 'pd-sec-workflow-notification';

    private const TEMPLATE = '@PimcoreCore/Workflow/NotificationEmail/notificationEmail.html.twig';

    private \Pimcore\Model\Asset\Folder $folder;

    private string $originalBaseUrl = '';

    protected function setUp(): void
    {
        $this->originalBaseUrl = $this->routerContext()->getBaseUrl();
        $this->ensureDomain();
        $this->deleteUser();
        $this->deleteAssetByPath('/' . self::FOLDER);
        \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'email' => 'workflow-recipient@example.test',
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
        ]);
        $this->folder = $this->createAssetFolder(1, self::FOLDER);
        $this->startCapturingMails();
    }

    protected function tearDown(): void
    {
        $this->stopCapturingMails();
        $this->routerContext()->setBaseUrl($this->originalBaseUrl);
        $this->deleteAssetByPath('/' . self::FOLDER);
        $this->restoreDomain();
        $this->deleteUser();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function baseUrlProvider(): array
    {
        return [
            'twig expression' => ['{{7*7}}', '%7B%7B7%2A7%7D%7D'],
            'twig statement' => ['{% set a = 1 %}x', '%7B%25%20set%20a%20%3D%201%20%25%7Dx'],
            'twig filter on empty string' => ["{{ ''|trans }}", '%7B%7B%20%27%27%7Ctrans%20%7D%7D'],
            'twig comment' => ['{# c #}', '%7B%23%20c%20%23%7D'],
            'path prefix with expression' => ['/proxy{{7*7}}', '/proxy%7B%7B7%2A7%7D%7D'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('baseUrlProvider')]
    public function testDeeplinkDoesNotCarryTemplateSyntaxFromTheRequestBaseUrl(string $baseUrl, string $expectedBaseUrl): void
    {
        $this->routerContext()->setBaseUrl($baseUrl);

        $this->notify();

        $this->assertDeeplinkIsMailed($expectedBaseUrl);
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

        $expectedLink = 'http://' . $this->domain . $expectedBaseUrl . '/admin/login/deeplink?asset_' . $this->folder->getId() . '_folder';
        $this->assertStringContainsString('<a href="' . $expectedLink . '"', $this->sentMails[0]['html']);
    }

    private function notify(): void
    {
        $service = \Pimcore::getContainer()->get(\Pimcore\Workflow\Notification\NotificationEmailService::class);
        \assert($service instanceof \Pimcore\Workflow\Notification\NotificationEmailService);

        $service->sendWorkflowEmailNotification(
            users: [self::USERNAME],
            roles: [],
            workflow: new \Symfony\Component\Workflow\Workflow(new \Symfony\Component\Workflow\Definition([], []), name: 'pd_sec_workflow'),
            subjectType: 'Asset',
            subject: $this->folder,
            action: 'publish',
            mailType: \Pimcore\Workflow\EventSubscriber\NotificationSubscriber::MAIL_TYPE_TEMPLATE,
            mailPath: self::TEMPLATE,
        );
    }

    private function routerContext(): \Symfony\Component\Routing\RequestContext
    {
        $router = \Pimcore::getContainer()->get('router');
        \assert($router instanceof \Symfony\Component\Routing\RouterInterface);

        return $router->getContext();
    }

    private function deleteUser(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
