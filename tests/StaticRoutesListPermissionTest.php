<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-23494')]
final class StaticRoutesListPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const ROUTE_NAME = 'pd-sec-listed-route';

    private const PATTERN = '/pd-sec-listed-route-pattern';

    private const USERNAME = 'pd-sec-routes-user';

    protected function setUp(): void
    {
        $this->removeFixtures();

        $route = new \Pimcore\Model\Staticroute();
        $route->setName(self::ROUTE_NAME);
        $route->setPattern(self::PATTERN);
        $route->setReverse(self::PATTERN);
        $route->setController('App\\Controller\\DefaultController::defaultAction');
        $route->save();
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    public function testUserWithoutAnyPermissionCannotListRoutes(): void
    {
        $this->authenticate($this->createUser([]));

        $this->assertListIsDenied();
    }

    public function testUserWithOnlyPredefinedPropertiesPermissionCannotListRoutes(): void
    {
        $this->authenticate($this->createUser(['predefined_properties']));

        $this->assertListIsDenied();
    }

    public function testUserWithOnlyPredefinedPropertiesPermissionCannotFilterRoutes(): void
    {
        $this->authenticate($this->createUser(['predefined_properties']));

        $this->assertListIsDenied(['filter' => 'pd-sec']);
    }

    public function testControlUserWithoutRoutesPermissionCannotModifyRoutes(): void
    {
        $this->authenticate($this->createUser(['predefined_properties']));
        $route = \Pimcore\Model\Staticroute::getByName(self::ROUTE_NAME);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->controller()->staticroutesAction($this->request([
            'xaction' => 'destroy',
            'data' => json_encode(['id' => $route->getId()], JSON_THROW_ON_ERROR),
        ]));
    }

    public function testControlUserWithRoutesPermissionSeesRoute(): void
    {
        $this->authenticate($this->createUser(['routes']));

        $payload = $this->listRoutes();

        $this->assertTrue($payload['success']);
        $this->assertSame([self::PATTERN], array_column(array_filter($payload['data'], static fn (array $row): bool => self::ROUTE_NAME === $row['name']), 'pattern'));
    }

    public function testControlAdminSeesRoute(): void
    {
        $this->authenticate($this->createUser([], admin: true));

        $payload = $this->listRoutes();

        $this->assertContains(self::ROUTE_NAME, array_column($payload['data'], 'name'));
    }

    /**
     * @param array<string, string> $parameters
     */
    private function assertListIsDenied(array $parameters = []): void
    {
        $thrown = null;
        $content = null;

        try {
            $content = $this->controller()->staticroutesAction($this->request($parameters))->getContent();
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class, $thrown, 'Route list was served: ' . $this->describe($content));
    }

    private function describe(?string $content): string
    {
        $rows = json_decode((string) $content, true)['data'] ?? [];

        return sprintf('%d routes, fixture listed: %s', count($rows), in_array(self::ROUTE_NAME, array_column($rows, 'name'), true) ? 'yes' : 'no');
    }

    /**
     * @return array{success: bool, data: list<array<string, mixed>>}
     */
    private function listRoutes(): array
    {
        return json_decode((string) $this->controller()->staticroutesAction($this->request([]))->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, string> $parameters
     */
    private function request(array $parameters): \Symfony\Component\HttpFoundation\Request
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: $parameters);
        $request->setMethod('POST');

        return $request;
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Admin\SettingsController
    {
        $container = \Pimcore::getContainer();

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\SettingsController($container->get('translator'));
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    /**
     * @param list<string> $permissions
     */
    private function createUser(array $permissions, bool $admin = false): \Pimcore\Model\User
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

    private function removeFixtures(): void
    {
        try {
            $this->deleteUserByName(self::USERNAME);
        } finally {
            foreach ((new \Pimcore\Model\Staticroute\Listing())->getRoutes() as $route) {
                if (self::ROUTE_NAME === $route->getName()) {
                    $route->delete();
                }
            }
        }
    }
}
