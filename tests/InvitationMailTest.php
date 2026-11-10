<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115898')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class InvitationMailTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MainDomainFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;

    private const USERNAME = 'pd-sec-invitation-user';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in  24 hours: \n\n";

    private \Pimcore\Model\User $user;

    private string $originalBaseUrl = '';

    protected function setUp(): void
    {
        $this->originalBaseUrl = $this->routerContext()->getBaseUrl();
        $this->ensureDomain();
        $this->deleteUser();
        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'email' => 'invitation-recipient@example.test',
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
        ]);
        $this->startCapturingMails();
    }

    protected function tearDown(): void
    {
        $this->stopCapturingMails();
        $this->routerContext()->setBaseUrl($this->originalBaseUrl);
        $this->restoreDomain();
        $this->deleteUser();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function baseUrlProvider(): array
    {
        return [
            'twig expression' => ['{{7*7}}'],
            'twig statement' => ['{% set a = 1 %}x'],
            'twig filter on empty string' => ["{{ ''|trans }}"],
            'twig comment' => ['{# c #}'],
            'twig template reference' => ['{{ _self }}'],
            'path prefix with expression' => ['/proxy{{7*7}}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('baseUrlProvider')]
    public function testInvitationLinkIsSentLiterallyWithTheRequestBaseUrl(string $baseUrl): void
    {
        $this->routerContext()->setBaseUrl($baseUrl);

        $this->assertInvitationIsMailed($baseUrl);
    }

    public function testControlPlainBaseUrlIsKeptInTheInvitationLink(): void
    {
        $this->routerContext()->setBaseUrl('/pim');

        $this->assertInvitationIsMailed('/pim');
    }

    private function assertInvitationIsMailed(string $expectedBaseUrl): void
    {
        $response = $this->controller()->invitationLinkAction(
            \Symfony\Component\HttpFoundation\Request::create(
                uri: '/admin/user/invitationlink',
                method: 'POST',
                parameters: ['username' => self::USERNAME],
            ),
            \Pimcore::getContainer()->get('translator'),
            \Pimcore::getContainer()->get('router'),
        );

        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue(json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR)['success']);
        $this->assertCount(1, $this->sentMails, 'exactly one invitation mail must be sent');
        $this->assertSame(['invitation-recipient@example.test'], $this->sentMails[0]['recipients']);
        $this->assertSame('Pimcore login invitation for ' . $this->domain, $this->sentMails[0]['subject']);

        $body = $this->sentMails[0]['text'];
        $matched = preg_match('~\?token=([^&\s]+)&reset=1$~', $body, $matches);
        $this->assertSame(1, $matched, 'the body must end with the reset link: ' . $body);
        $this->assertSame(self::MAIL_INTRO . 'http://' . $this->domain . $expectedBaseUrl . '/admin/login/login?token=' . $matches[1] . '&reset=1', $body);
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($matches[1]))?->getId());
    }

    private function routerContext(): \Symfony\Component\Routing\RequestContext
    {
        $router = \Pimcore::getContainer()->get('router');
        \assert($router instanceof \Symfony\Component\Routing\RouterInterface);

        return $router->getContext();
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Admin\UserController
    {
        $container = \Pimcore::getContainer();

        if ($container->has(\Pimcore\Bundle\AdminBundle\Controller\Admin\UserController::class)) {
            return $container->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\UserController::class);
        }

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\UserController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    private function deleteUser(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
