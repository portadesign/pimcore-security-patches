<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-23492')]
final class SearchBrickInjectionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-search-brick-user';

    private const UNKNOWN_BRICK = 'PDSECNOSUCHBRICKMARKER';

    private \Pimcore\Model\User $user;

    private int $expectedSportsCarCount;

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['objects']);

        $workspace = new \Pimcore\Model\User\Workspace\DataObject();
        $workspace->setCid(1);
        $workspace->setCpath('/');
        $workspace->setList(true);
        $workspace->setView(true);
        $this->user->setWorkspacesObject([$workspace]);
        $this->user->save();

        $this->authenticate(\Pimcore\Model\User::getById($this->user->getId()));

        $this->expectedSportsCarCount = (int) \Pimcore\Db::get()->fetchOne(
            "SELECT COUNT(*) FROM object_query_CAR WHERE carClass LIKE '%sports%'",
        );
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->deleteUserByName(self::USERNAME);
    }

    public function testUnknownBrickTokenIsRejectedBeforeTheJoinIsBuilt(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Check your arguments.');

        $this->find([self::UNKNOWN_BRICK . '~x']);
    }

    public function testControlRealBrickStillJoins(): void
    {
        $response = $this->find(['Engine~cylinders']);

        $payload = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        $this->assertTrue($payload['success']);
        $this->assertSame($this->expectedSportsCarCount, (int) $payload['total']);
    }

    /**
     * @param list<string> $fields
     */
    private function find(array $fields): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Searchadmin\SearchController::class);

        $request = new \Symfony\Component\HttpFoundation\Request([
            'type' => 'object',
            'class' => 'Car',
            'start' => 0,
            'limit' => 50,
            'filter' => json_encode([[
                'property' => 'carClass',
                'operator' => 'like',
                'type' => 'string',
                'value' => 'sports',
            ]], JSON_THROW_ON_ERROR),
            'fields' => $fields,
        ]);

        return $controller->findAction(
            $request,
            new \Symfony\Component\EventDispatcher\EventDispatcher(),
            new \Pimcore\Bundle\AdminBundle\Helper\GridHelperService(),
        );
    }
}
