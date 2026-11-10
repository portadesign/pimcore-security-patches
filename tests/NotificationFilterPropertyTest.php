<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115891')]
final class NotificationFilterPropertyTest extends \PHPUnit\Framework\TestCase
{
    private const USERNAME = 'pd-sec-notification-user';

    private const TITLE = 'pd-sec-notification-title';

    private \Pimcore\Model\User $user;

    protected function setUp(): void
    {
        $this->removeFixtures();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['notifications']);
        $this->user->save();

        $this->service()->sendToUser(
            userId: (int) $this->user->getId(),
            fromUser: (int) $this->user->getId(),
            title: self::TITLE,
            message: 'pd-sec-notification-message',
        );
    }

    protected function tearDown(): void
    {
        $this->removeFixtures();
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function injectedPropertyProvider(): array
    {
        return [
            'string, always-true subselect' => ['string', '(SELECT 1)-- -', 'like'],
            'string, time based' => ['string', '(SELECT 1 FROM (SELECT SLEEP(1))t)-- -', 'like'],
            'string, other column' => ['string', 'message', 'like'],
            'date, always-true subselect' => ['date', '(SELECT 1)-- -', 'gt'],
            'date, raw column' => ['date', 'creationDate', 'gt'],
            'date between, subselect' => ['date', '(SELECT 1)-- -', 'eq'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('injectedPropertyProvider')]
    public function testUnknownPropertyIsRejected(string $type, string $property, string $operator): void
    {
        $started = microtime(true);

        try {
            $this->find([['type' => $type, 'property' => $property, 'operator' => $operator, 'value' => 'date' === $type ? '2020-01-01' : 'pd-sec-no-match']]);
            $this->fail('A filter property outside the allowlist was accepted');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }

        $this->assertLessThan(1.0, microtime(true) - $started);
    }

    public function testNonStringPropertyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->find([['type' => 'string', 'property' => ['title'], 'operator' => 'like', 'value' => 'x']]);
    }

    public function testMissingPropertyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->find([['type' => 'string', 'operator' => 'like', 'value' => 'x']]);
    }

    public function testTitleFilterFindsTheNotification(): void
    {
        $titles = $this->find([['type' => 'string', 'property' => 'title', 'operator' => 'like', 'value' => 'sec-notification']]);

        $this->assertSame([self::TITLE], $titles);
    }

    public function testTitleFilterExcludesNonMatchingNotification(): void
    {
        $titles = $this->find([['type' => 'string', 'property' => 'title', 'operator' => 'like', 'value' => 'pd-sec-no-match']]);

        $this->assertSame([], $titles);
    }

    public function testTimestampFilterIsMappedToTheCreationDate(): void
    {
        $yesterday = (new \DateTimeImmutable('-1 day'))->format('Y-m-d');
        $tomorrow = (new \DateTimeImmutable('+1 day'))->format('Y-m-d');

        $this->assertSame([self::TITLE], $this->find([['type' => 'date', 'property' => 'timestamp', 'operator' => 'gt', 'value' => $yesterday]]));
        $this->assertSame([], $this->find([['type' => 'date', 'property' => 'timestamp', 'operator' => 'gt', 'value' => $tomorrow]]));
        $this->assertSame([self::TITLE], $this->find([['type' => 'date', 'property' => 'timestamp', 'operator' => 'eq', 'value' => date('Y-m-d')]]));
    }

    /**
     * @param list<array<string, mixed>> $items
     *
     * @return list<string>
     */
    private function find(array $items): array
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: ['filter' => json_encode($items, JSON_THROW_ON_ERROR)]);
        $filter = ['recipient' => (int) $this->user->getId()];

        foreach ((new \Pimcore\Model\Notification\Service\NotificationServiceFilterParser($request))->parse() as $key => $value) {
            $filter[$key] = $value;
        }

        $result = $this->service()->findAll($filter, ['offset' => 0, 'limit' => 50]);

        return array_map(
            static fn (\Pimcore\Model\Notification $notification): string => (string) $notification->getTitle(),
            $result['data'],
        );
    }

    private function service(): \Pimcore\Model\Notification\Service\NotificationService
    {
        $service = \Pimcore::getContainer()->get(\Pimcore\Model\Notification\Service\NotificationService::class);
        \assert($service instanceof \Pimcore\Model\Notification\Service\NotificationService);

        return $service;
    }

    private function removeFixtures(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $this->service()->deleteAll((int) $existing->getId());
            $existing->delete();
        }
    }
}
