<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2024-24822')]
final class TagsPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\HostResidueGuard;

    private const USERNAME = 'pd-sec-tags-user';

    private const FOLDER = 'pd-sec-tags';

    private const TAG_PREFIX = 'pd-sec-tag';

    private const ROOT = 'pd-sec-tag-root';

    private const CHILD = 'pd-sec-tag-child';

    private const VICTIM = 'pd-sec-tag-victim';

    private const RENAMEE = 'pd-sec-tag-renamee';

    private const ASSIGNED = 'pd-sec-tag-assigned';

    private const TO_ASSIGN = 'pd-sec-tag-toassign';

    private const CREATED = 'pd-sec-tag-created';

    private const RENAMED = 'pd-sec-tag-renamed';

    private const CONFIGURATION_ACTIONS = ['add', 'delete', 'update'];

    private const ASSIGNMENT_ACTIONS = ['loadForElement', 'addToElement', 'removeFromElement', 'batchJobs', 'doBatch'];

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\Asset\Folder $folder;

    private \Pimcore\Model\Asset $asset;

    /**
     * @var array<string, \Pimcore\Model\Element\Tag>
     */
    private array $tags = [];

    protected function setUp(): void
    {
        $this->removeFixtures();

        $this->folder = $this->createAssetFolder(parentId: 1, filename: self::FOLDER);
        $this->asset = \Pimcore\Model\Asset::create($this->folder->getId(), ['filename' => 'child.txt', 'data' => 'pd-sec-tags']);

        $this->tags[self::ROOT] = $this->createTag(self::ROOT, 0);
        $this->tags[self::CHILD] = $this->createTag(self::CHILD, $this->tags[self::ROOT]->getId());
        foreach ([self::VICTIM, self::RENAMEE, self::ASSIGNED, self::TO_ASSIGN] as $name) {
            $this->tags[$name] = $this->createTag($name, 0);
        }
        \Pimcore\Model\Element\Tag::addTagToElement('asset', $this->folder->getId(), $this->tags[self::ASSIGNED]);

        $this->user = $this->createUser(['assets']);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function actionProvider(): array
    {
        return [
            'add' => ['add'],
            'delete' => ['delete'],
            'update' => ['update'],
            'tree children' => ['tree'],
            'load tags of element' => ['loadForElement'],
            'add tag to element' => ['addToElement'],
            'remove tag from element' => ['removeFromElement'],
            'batch assignment jobs' => ['batchJobs'],
            'do batch assignment' => ['doBatch'],
        ];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function wrongPermissionProvider(): array
    {
        $cases = [];
        foreach (self::CONFIGURATION_ACTIONS as $action) {
            foreach (['tags_assignment', 'tags_search'] as $permission) {
                $cases[$action . ' with ' . $permission] = [$action, $permission];
            }
        }
        foreach (self::ASSIGNMENT_ACTIONS as $action) {
            foreach (['tags_configuration', 'tags_search'] as $permission) {
                $cases[$action . ' with ' . $permission] = [$action, $permission];
            }
        }

        return $cases;
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function rightPermissionProvider(): array
    {
        $cases = [];
        foreach (self::CONFIGURATION_ACTIONS as $action) {
            $cases[$action] = [$action, 'tags_configuration'];
        }
        foreach (self::ASSIGNMENT_ACTIONS as $action) {
            $cases[$action] = [$action, 'tags_assignment'];
        }

        return $cases;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function treePermissionProvider(): array
    {
        return [
            'tags_configuration' => ['tags_configuration'],
            'tags_assignment' => ['tags_assignment'],
            'tags_search' => ['tags_search'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('actionProvider')]
    public function testUserWithoutTagPermissionIsDeniedAndNothingChanges(string $action): void
    {
        $this->assertDeniedWithoutChange($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('wrongPermissionProvider')]
    public function testUserWithOnlyTheOtherTagPermissionIsDeniedAndNothingChanges(string $action, string $permission): void
    {
        $this->grantPermission($permission);

        $this->assertDeniedWithoutChange($action);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('rightPermissionProvider')]
    public function testControlUserWithRequiredPermissionPerformsAction(string $action, string $permission): void
    {
        $this->grantPermission($permission);
        $before = $this->snapshot();

        $response = $this->perform($action);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame($this->expectedAfter($action, $before), $this->snapshot());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('treePermissionProvider')]
    public function testControlTreeChildrenAreListedWithAnyTagPermission(string $permission): void
    {
        $this->grantPermission($permission);

        $payload = json_decode((string) $this->perform('tree')->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame([self::CHILD], array_column($payload, 'text'));
    }

    public function testControlLoadedTagsOfElementContainAssignedTag(): void
    {
        $this->grantPermission('tags_assignment');

        $payload = json_decode((string) $this->perform('loadForElement')->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame([self::ASSIGNED], array_column($payload, 'text'));
    }

    public function testControlBatchJobsListChildAssetOfFolder(): void
    {
        $this->grantPermission('tags_assignment');

        $payload = json_decode((string) $this->perform('batchJobs')->getContent(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame([[$this->asset->getId()]], $payload['idLists']);
    }

    private function assertDeniedWithoutChange(string $action): void
    {
        $before = $this->snapshot();
        $thrown = null;
        $content = null;

        try {
            $content = $this->perform($action)->getContent();
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(
            \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException::class,
            $thrown,
            sprintf('Action %s ran; state %s; response %s', $action, $before === $this->snapshot() ? 'unchanged' : 'CHANGED', $content),
        );
        $this->assertSame($before, $this->snapshot());
    }

    private function perform(string $action): \Symfony\Component\HttpFoundation\JsonResponse
    {
        $controller = $this->controller();
        $assetFolderId = $this->folder->getId();

        return match ($action) {
            'add' => $controller->addAction(new \Symfony\Component\HttpFoundation\Request(request: ['text' => self::CREATED, 'parentId' => $this->tags[self::ROOT]->getId()])),
            'delete' => $controller->deleteAction(new \Symfony\Component\HttpFoundation\Request(query: ['id' => $this->tags[self::VICTIM]->getId()])),
            'update' => $controller->updateAction(new \Symfony\Component\HttpFoundation\Request(request: ['id' => $this->tags[self::RENAMEE]->getId(), 'text' => self::RENAMED])),
            'tree' => $controller->treeGetChildrenByIdAction(new \Symfony\Component\HttpFoundation\Request(query: ['node' => $this->tags[self::ROOT]->getId()])),
            'loadForElement' => $controller->loadTagsForElementAction(new \Symfony\Component\HttpFoundation\Request(query: ['assignmentCId' => $assetFolderId, 'assignmentCType' => 'asset'])),
            'addToElement' => $controller->addTagToElementAction(new \Symfony\Component\HttpFoundation\Request(request: ['assignmentElementId' => $assetFolderId, 'assignmentElementType' => 'asset', 'tagId' => $this->tags[self::TO_ASSIGN]->getId()])),
            'removeFromElement' => $controller->removeTagFromElementAction(new \Symfony\Component\HttpFoundation\Request(query: ['assignmentElementId' => $assetFolderId, 'assignmentElementType' => 'asset', 'tagId' => $this->tags[self::ASSIGNED]->getId()])),
            'batchJobs' => $controller->getBatchAssignmentJobsAction(
                new \Symfony\Component\HttpFoundation\Request(query: ['elementId' => $assetFolderId, 'elementType' => 'asset']),
                \Pimcore::getContainer()->get('event_dispatcher'),
            ),
            'doBatch' => $controller->doBatchAssignmentAction(new \Symfony\Component\HttpFoundation\Request(request: [
                'elementType' => 'asset',
                'assignedTags' => json_encode([$this->tags[self::TO_ASSIGN]->getId()], JSON_THROW_ON_ERROR),
                'childrenIds' => json_encode([$this->asset->getId()], JSON_THROW_ON_ERROR),
                'removeAndApply' => 'false',
            ])),
        };
    }

    /**
     * @param array{tags: array<string, string>, assignments: list<string>} $before
     *
     * @return array{tags: array<string, string>, assignments: list<string>}
     */
    private function expectedAfter(string $action, array $before): array
    {
        $after = $before;
        $folderAssignment = fn (string $tag): string => $tag . '@asset:/' . self::FOLDER;

        switch ($action) {
            case 'add':
                $after['tags'][self::CREATED] = self::ROOT;

                break;
            case 'delete':
                unset($after['tags'][self::VICTIM]);

                break;
            case 'update':
                unset($after['tags'][self::RENAMEE]);
                $after['tags'][self::RENAMED] = '';

                break;
            case 'addToElement':
                $after['assignments'][] = $folderAssignment(self::TO_ASSIGN);

                break;
            case 'removeFromElement':
                $after['assignments'] = [];

                break;
            case 'doBatch':
                $after['assignments'][] = self::TO_ASSIGN . '@asset:/' . self::FOLDER . '/child.txt';

                break;
        }

        ksort($after['tags']);
        sort($after['assignments']);

        return $after;
    }

    /**
     * @return array{tags: array<string, string>, assignments: list<string>}
     */
    private function snapshot(): array
    {
        $db = \Pimcore\Db::get();
        $names = $db->fetchAllKeyValue('SELECT id, name FROM tags WHERE name LIKE ?', [self::TAG_PREFIX . '%']);

        $tags = [];
        foreach ($db->fetchAllAssociative('SELECT id, name, parentId FROM tags WHERE name LIKE ?', [self::TAG_PREFIX . '%']) as $row) {
            $tags[$row['name']] = $names[$row['parentId']] ?? '';
        }
        ksort($tags);

        $assignments = [];
        foreach ($db->fetchAllAssociative('SELECT tagid, ctype, cid FROM tags_assignment WHERE tagid IN (SELECT id FROM tags WHERE name LIKE ?)', [self::TAG_PREFIX . '%']) as $row) {
            $element = \Pimcore\Model\Asset::getById((int) $row['cid'], ['force' => true]);
            $assignments[] = $names[$row['tagid']] . '@' . $row['ctype'] . ':' . $element?->getRealFullPath();
        }
        sort($assignments);

        return ['tags' => $tags, 'assignments' => $assignments];
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Admin\TagsController
    {
        $container = \Pimcore::getContainer();

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\TagsController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    private function createTag(string $name, int $parentId): \Pimcore\Model\Element\Tag
    {
        $tag = new \Pimcore\Model\Element\Tag();
        $tag->setName($name);
        $tag->setParentId($parentId);
        $tag->save();

        return $tag;
    }

    /**
     * @param list<string> $permissions
     */
    private function createUser(array $permissions): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $user->setPermissions($permissions);

        $workspace = new \Pimcore\Model\User\Workspace\Asset();
        $workspace->setCid($this->folder->getId());
        $workspace->setCpath($this->folder->getRealFullPath());
        $workspace->setView(true);
        $workspace->setList(true);
        $user->setWorkspacesAsset([$workspace]);
        $user->save();
        $this->authenticate($user);

        return $user;
    }

    private function grantPermission(string $permission): void
    {
        $this->user->setPermissions(['assets', $permission]);
        $this->user->save();
        $this->authenticate($this->user);
    }

    private function removeFixtures(): void
    {
        try {
            $this->deleteUserByName(self::USERNAME);
        } finally {
            try {
                $this->deleteTags();
            } finally {
                $this->deleteAssetByPath('/' . self::FOLDER);
            }
        }
    }

    private function deleteTags(): void
    {
        $list = new \Pimcore\Model\Element\Tag\Listing();
        $list->setCondition('name LIKE ?', [self::TAG_PREFIX . '%']);

        foreach ($list->load() as $tag) {
            \Pimcore\Model\Element\Tag::getById($tag->getId())?->delete();
        }

        $this->tags = [];
    }
}
