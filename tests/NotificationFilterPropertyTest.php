<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115891')]
final class NotificationFilterPropertyTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-notification-user';

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->deleteUserByName(self::USERNAME);
    }

    /**
     * @return array<string, array{mixed, mixed, mixed}>
     */
    public static function injectedPropertyProvider(): array
    {
        return [
            'unknown column' => ['string', 'message', 'like'],
            'always-true subselect' => ['string', '(SELECT 1)-- -', 'like'],
            'time-based subselect' => ['string', '(SELECT 1 FROM (SELECT SLEEP(1))t)-- -', 'like'],
            'mapped target used as property' => ['date', 'creationDate', 'gt'],
            'case variant of an allowed property' => ['string', 'Title', 'like'],
            'trailing space on an allowed property' => ['string', 'title ', 'like'],
            'loose true type and operator carry an injection' => [true, '(SELECT 1)-- -', true],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('injectedPropertyProvider')]
    public function testUnknownPropertyIsRejected(mixed $type, mixed $property, mixed $operator): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->parse([['type' => $type, 'property' => $property, 'operator' => $operator, 'value' => '2020-01-01']]);
    }

    public function testNonStringPropertyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->parse([['type' => 'string', 'property' => ['title'], 'operator' => 'like', 'value' => 'x']]);
    }

    public function testIntegerZeroPropertyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->parse([['type' => 'string', 'property' => 0, 'operator' => 'like', 'value' => 'x']]);
    }

    public function testMissingPropertyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->parse([['type' => 'string', 'operator' => 'like', 'value' => 'x']]);
    }

    public function testTitleFilterMapsToTheTitleColumn(): void
    {
        $parsed = $this->parse([['type' => 'string', 'property' => 'title', 'operator' => 'like', 'value' => 'needle']]);

        $this->assertSame(['title LIKE ?' => '%needle%'], $parsed);
    }

    public function testDateFilterMapsToTheCreationDateColumn(): void
    {
        $parsed = $this->parse([['type' => 'date', 'property' => 'date', 'operator' => 'gt', 'value' => '2020-01-01']]);

        $this->assertSame(['creationDate > ?'], array_keys($parsed));
    }

    public function testDateEqualityFilterMapsToACreationDateRange(): void
    {
        $parsed = $this->parse([['type' => 'date', 'property' => 'date', 'operator' => 'eq', 'value' => '2020-01-01']]);

        $this->assertSame(['creationDate BETWEEN ? AND ?'], array_keys($parsed));
    }

    public function testFindAllActionRejectsAnInjectedProperty(): void
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $user->setPermissions(['notifications']);
        $user->save();
        $this->authenticate(\Pimcore\Model\User::getById($user->getId()));

        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\NotificationController::class);
        $request = new \Symfony\Component\HttpFoundation\Request([
            'filter' => json_encode([['type' => 'string', 'property' => '(SELECT 1)-- -', 'operator' => 'like', 'value' => 'x']], JSON_THROW_ON_ERROR),
        ]);

        $this->expectException(\InvalidArgumentException::class);

        $controller->findAllAction($request, $this->service());
    }

    /**
     * @param list<array<string, mixed>> $items
     *
     * @return array<string, mixed>
     */
    private function parse(array $items): array
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: ['filter' => json_encode($items, JSON_THROW_ON_ERROR)]);

        return (new \Pimcore\Model\Notification\Service\NotificationServiceFilterParser($request))->parse();
    }

    private function service(): \Pimcore\Model\Notification\Service\NotificationService
    {
        $service = \Pimcore::getContainer()->get(\Pimcore\Model\Notification\Service\NotificationService::class);
        \assert($service instanceof \Pimcore\Model\Notification\Service\NotificationService);

        return $service;
    }
}
