<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2024-41109')]
final class IndexStatisticsPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-statistics-user';

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->deleteUserByName(self::USERNAME);
    }

    public function testUserWithoutSystemSettingsCannotReadStatistics(): void
    {
        $this->authenticate($this->createUser(['assets', 'documents', 'objects'], admin: false));

        $thrown = null;
        $content = null;

        try {
            $content = $this->statistics(xhr: true)->getContent();
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(
            \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class,
            $thrown,
            'Statistics were served: ' . substr((string) $content, 0, 200),
        );
    }

    public function testControlUserWithSystemSettingsReadsStatistics(): void
    {
        $this->authenticate($this->createUser(['system_settings'], admin: false));

        $payload = $this->payload($this->statistics(xhr: true));

        $this->assertSame(\Pimcore\Version::getVersion(), $payload['pimcore_version']);
        $this->assertContains('users', array_column($payload['tables'], 'name'));
    }

    public function testControlAdminReadsStatistics(): void
    {
        $this->authenticate($this->createUser([], admin: true));

        $payload = $this->payload($this->statistics(xhr: true));

        $this->assertSame(\Pimcore\Version::getVersion(), $payload['pimcore_version']);
        $this->assertContains('users', array_column($payload['tables'], 'name'));
    }

    public function testControlAdminWithoutXmlHttpRequestIsStillDenied(): void
    {
        $this->authenticate($this->createUser([], admin: true));

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->statistics(xhr: false);
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(\Symfony\Component\HttpFoundation\JsonResponse $response): array
    {
        return json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }

    private function statistics(bool $xhr): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $container = \Pimcore::getContainer();

        $controller = (new \ReflectionClass(\Pimcore\Bundle\AdminBundle\Controller\Admin\IndexController::class))->newInstanceWithoutConstructor();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        $request = new \Symfony\Component\HttpFoundation\Request();
        if ($xhr) {
            $request->headers->set('X-Requested-With', 'XMLHttpRequest');
        }

        return $controller->statisticsAction($request, \Pimcore\Db::get(), $container->get('kernel'));
    }

    /**
     * @param list<string> $permissions
     */
    private function createUser(array $permissions, bool $admin): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => $admin,
        ]);
        $user->setPermissions($permissions);
        $user->save();

        return $user;
    }
}
