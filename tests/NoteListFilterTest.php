<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-006')]
final class NoteListFilterTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\HostResidueGuard;

    private const USERNAME = 'pd-sec-notelist-user';

    private const MARKER = 'pd-sec-notelist-marker';

    private \Pimcore\Model\User $user;

    /**
     * @var list<int>
     */
    private array $noteIds = [];

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);
        $this->removeFixtureNotes();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['notes_events']);
        $this->user->save();

        $this->authenticate(\Pimcore\Model\User::getById($this->user->getId()));

        foreach (['a', 'b'] as $suffix) {
            $note = new \Pimcore\Model\Element\Note();
            $note->setCid(1);
            $note->setCtype('asset');
            $note->setDate(time());
            $note->setType(self::MARKER);
            $note->setTitle(self::MARKER . '-' . $suffix);
            $note->save();
            $this->noteIds[] = $note->getId();
        }
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtureNotes();
        $this->deleteUserByName(self::USERNAME);
    }

    public function testBacktickBreakoutThroughDateEqualityPropertyIsRejectedNotExecuted(): void
    {
        $response = $this->noteList([
            ['property' => 'type', 'operator' => 'eq', 'type' => 'string', 'value' => self::MARKER],
            ['property' => 'date` = 0 OR `1', 'operator' => 'eq', 'type' => 'date', 'value' => date('Y-m-d')],
        ]);

        $payload = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        $this->assertTrue($payload['success']);
        $this->assertSame(2, (int) $payload['total']);
    }

    public function testControlTypeFilterStillMatchesFixtureNotes(): void
    {
        $response = $this->noteList([
            ['property' => 'type', 'operator' => 'eq', 'type' => 'string', 'value' => self::MARKER],
        ]);

        $payload = json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);

        $this->assertTrue($payload['success']);
        $this->assertSame(2, (int) $payload['total']);
    }

    /**
     * @param list<array<string, mixed>> $filters
     */
    private function noteList(array $filters): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\ElementController::class);

        $request = new \Symfony\Component\HttpFoundation\Request([
            'limit' => 50,
            'start' => 0,
            'filter' => json_encode($filters, JSON_THROW_ON_ERROR),
        ]);

        return $controller->noteListAction($request);
    }

    private function removeFixtureNotes(): void
    {
        foreach ($this->noteIds as $id) {
            $note = \Pimcore\Model\Element\Note::getById($id);

            if ($note instanceof \Pimcore\Model\Element\Note) {
                $note->delete();
            }
        }

        $this->noteIds = [];

        $db = \Pimcore\Db::get();
        $stray = $db->fetchFirstColumn('SELECT id FROM notes WHERE title LIKE ?', [self::MARKER . '%']);
        foreach ($stray as $id) {
            $note = \Pimcore\Model\Element\Note::getById((int) $id);

            if ($note instanceof \Pimcore\Model\Element\Note) {
                $note->delete();
            }
        }
    }
}
