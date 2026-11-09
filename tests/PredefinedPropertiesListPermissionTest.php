<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-23495')]
final class PredefinedPropertiesListPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const PROPERTY_KEY = 'pd-sec-listed-property';

    private const PROPERTY_NAME = 'pd-sec-listed-property-name';

    private const USERNAME = 'pd-sec-properties-user';

    protected function setUp(): void
    {
        $this->removeFixtures();

        $property = \Pimcore\Model\Property\Predefined::create();
        $property->setKey(self::PROPERTY_KEY);
        $property->setName(self::PROPERTY_NAME);
        $property->setType('text');
        $property->setCtype('document');
        $property->save();
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    public function testUserWithoutAnyPermissionCannotListProperties(): void
    {
        $this->authenticate($this->createUser([]));

        $this->assertListIsDenied();
    }

    public function testUserWithOnlyRoutesPermissionCannotListProperties(): void
    {
        $this->authenticate($this->createUser(['routes']));

        $this->assertListIsDenied();
    }

    public function testUserWithOnlyRoutesPermissionCannotFilterProperties(): void
    {
        $this->authenticate($this->createUser(['routes']));

        $this->assertListIsDenied(['filter' => 'pd-sec']);
    }

    public function testControlUserWithoutPredefinedPropertiesPermissionCannotModifyProperties(): void
    {
        $this->authenticate($this->createUser(['routes']));
        $property = \Pimcore\Model\Property\Predefined::getByKey(self::PROPERTY_KEY);

        $this->expectException(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class);

        $this->controller()->propertiesAction($this->request([
            'xaction' => 'destroy',
            'data' => json_encode(['id' => $property->getId()], JSON_THROW_ON_ERROR),
        ]));
    }

    public function testControlUserWithPredefinedPropertiesPermissionSeesProperty(): void
    {
        $this->authenticate($this->createUser(['predefined_properties']));

        $payload = $this->listProperties();

        $this->assertTrue($payload['success']);
        $this->assertSame([self::PROPERTY_NAME], array_column(array_filter($payload['data'], static fn (array $row): bool => self::PROPERTY_KEY === $row['key']), 'name'));
    }

    public function testControlAdminSeesProperty(): void
    {
        $this->authenticate($this->createUser([], admin: true));

        $payload = $this->listProperties();

        $this->assertContains(self::PROPERTY_KEY, array_column($payload['data'], 'key'));
    }

    /**
     * @param array<string, string> $parameters
     */
    private function assertListIsDenied(array $parameters = []): void
    {
        $thrown = null;
        $content = null;

        try {
            $content = $this->controller()->propertiesAction($this->request($parameters))->getContent();
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class, $thrown, 'Property list was served: ' . $this->describe($content));
    }

    private function describe(?string $content): string
    {
        $rows = json_decode((string) $content, true)['data'] ?? [];

        return sprintf('%d properties, fixture listed: %s', count($rows), in_array(self::PROPERTY_KEY, array_column($rows, 'key'), true) ? 'yes' : 'no');
    }

    /**
     * @return array{success: bool, data: list<array<string, mixed>>}
     */
    private function listProperties(): array
    {
        return json_decode((string) $this->controller()->propertiesAction($this->request([]))->getContent(), true, 512, JSON_THROW_ON_ERROR);
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
            foreach ((new \Pimcore\Model\Property\Predefined\Listing())->getProperties() as $property) {
                if (self::PROPERTY_KEY === $property->getKey()) {
                    $property->delete();
                }
            }
        }
    }
}
