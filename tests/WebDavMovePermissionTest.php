<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45260')]
final class WebDavMovePermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;

    private const USERNAME = 'pd-sec-webdav-user';

    private const ADMIN_USERNAME = 'pd-sec-webdav-admin';

    private const FOLDER = 'pd-sec-webdav';

    private const SOURCE_DATA = 'pd-sec-webdav-source-data';

    private const EXISTING_DATA = 'pd-sec-webdav-existing-data';

    private const GHOST_DATA = 'pd-sec-webdav-ghost-data';

    private const BASE_URI = '/asset/webdav/';

    private const ALL_RIGHTS = ['view' => true, 'list' => true, 'rename' => true, 'publish' => true, 'create' => true, 'delete' => true, 'settings' => true];

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $admin;

    private \Pimcore\Model\Asset\Folder $folder;

    private \Pimcore\Model\Asset\Folder $subfolder;

    private \Pimcore\Model\Asset $source;

    private \Pimcore\Model\Asset $existing;

    protected function setUp(): void
    {
        $this->removeFixtures();

        $this->folder = $this->createAssetFolder(parentId: 1, filename: self::FOLDER);
        $this->subfolder = $this->createAssetFolder(parentId: $this->folder->getId(), filename: 'sub');
        $this->source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $this->existing = $this->createTextAsset('existing.txt', self::EXISTING_DATA);

        $this->admin = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::ADMIN_USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => false,
            'admin' => true,
        ]);
        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => false,
        ]);
        $this->user->setPermissions(['assets']);
        $this->grantWorkspace(['view' => true]);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    public function testViewOnlyUserCannotRenameWithinFolder(): void
    {
        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/renamed.txt'));
    }

    public function testViewOnlyUserCannotMoveToAnotherFolder(): void
    {
        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/source.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub/source.txt'));
    }

    public function testCoreFileDeleteGuardRejectsOverwriteWithoutDeleteRight(): void
    {
        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/existing.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
    }

    public function testViewOnlyUserCannotOverwriteExistingAssetThroughTree(): void
    {
        $tree = new \Pimcore\Model\Asset\WebDAV\Tree(new \Pimcore\Model\Asset\WebDAV\Folder(\Pimcore\Model\Asset::getById(1)));

        $thrown = null;
        try {
            $tree->move(self::FOLDER . '/source.txt', self::FOLDER . '/existing.txt');
        } catch (\Sabre\DAV\Exception\Forbidden $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Sabre\DAV\Exception\Forbidden::class, $thrown);
        $this->assertFixturesUnchanged();
    }

    public function testUserWithoutPublishCannotOverwriteExistingAssetAndDestinationSurvives(): void
    {
        $this->grantWorkspace(['view' => true, 'list' => true, 'delete' => true]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/existing.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
    }

    public function testViewOnlyUserCannotResurrectDeleteLoggedPath(): void
    {
        $ghostId = $this->deleteGhostAsAdmin();
        $this->grantWorkspace(['view' => true]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(403, $status);
        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/ghost.txt'));
        $this->assertNull(\Pimcore\Model\Asset::getById($ghostId, ['force' => true]));
    }

    public function testUserWithoutDeleteOnSourceCannotMoveOverDeleteLoggedPath(): void
    {
        $this->deleteGhostAsAdmin();
        $this->grantWorkspace(['view' => true, 'list' => true, 'rename' => true, 'publish' => true, 'create' => true]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(403, $status);
        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/ghost.txt'));
    }

    public function testUserWithoutDeleteOnSourceCannotOverwriteExistingAssetAndDestinationSurvives(): void
    {
        $this->grant([
            $this->workspace($this->folder, self::ALL_RIGHTS),
            $this->workspace($this->source, ['view' => true, 'list' => true, 'rename' => true, 'publish' => true, 'create' => true]),
        ]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/existing.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
    }

    public function testFailingSaveOfAuthorisedMoveIsNotReportedAsSuccess(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $deepFolder = $this->createDeepFolder();
        $deepPath = $deepFolder->getRealFullPath();

        $status = $this->request('MOVE', '/' . self::FOLDER . '/source.txt', $deepPath . '/moved.txt', unexpectedAsServerError: true);

        $this->assertSame(500, $status);
        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath($deepPath . '/moved.txt'));
        $this->assertSame(0, \Pimcore\Model\Asset::getById($deepFolder->getId(), ['force' => true])?->getChildAmount());
    }

    public function testUserWithoutCreateOnDestinationFolderCannotMoveAcrossFolders(): void
    {
        $this->grant([
            $this->workspace($this->folder, self::ALL_RIGHTS),
            $this->workspace($this->subfolder, ['view' => true, 'list' => true, 'rename' => true, 'publish' => true, 'delete' => true]),
        ]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/source.txt');

        $this->assertSame(403, $status);
        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub/source.txt'));
    }

    public function testUserWithoutPublishOnAssetCannotMoveAcrossFolders(): void
    {
        $this->grant([
            $this->workspace($this->folder, ['view' => true, 'list' => true, 'rename' => true, 'delete' => true]),
            $this->workspace($this->subfolder, ['view' => true, 'list' => true, 'create' => true]),
        ]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/source.txt');

        $this->assertSame(403, $status);
        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub/source.txt'));
    }

    public function testUserWithoutRenameCannotRenameWithinFolder(): void
    {
        $this->grantWorkspace(['view' => true, 'list' => true, 'create' => true, 'publish' => true, 'delete' => true]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/renamed.txt'));
    }

    public function testUserWithRenameCreatePublishAndDeleteCanRenameWithinFolder(): void
    {
        $this->grantWorkspace(['view' => true, 'list' => true, 'rename' => true, 'create' => true, 'publish' => true, 'delete' => true]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(201, $status);
        $renamed = \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/renamed.txt');
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $renamed);
        $this->assertSame($this->source->getId(), $renamed->getId());
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/source.txt'));
    }

    public function testRenameRecordsActingUserAsModifier(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $this->assertNotSame($this->user->getId(), $this->reloadedSource()->getUserModification());

        $this->assertSame(201, $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt'));

        $this->assertSame($this->user->getId(), $this->reloadedSource()->getUserModification());
    }

    public function testCrossFolderMoveRecordsActingUserAsModifier(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $this->assertNotSame($this->user->getId(), $this->reloadedSource()->getUserModification());

        $this->assertSame(201, $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/source.txt'));

        $moved = $this->reloadedSource();
        $this->assertSame('/' . self::FOLDER . '/sub/source.txt', $moved->getRealFullPath());
        $this->assertSame($this->user->getId(), $moved->getUserModification());
    }

    public function testOverwriteRecordsActingUserAsModifierOfSurvivingAsset(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);

        $this->assertSame(204, $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/existing.txt'));

        $existing = \Pimcore\Model\Asset::getById($this->existing->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $existing);
        $this->assertSame($this->user->getId(), $existing->getUserModification());
    }

    public function testMoveOfMissingSourceIsNotFound(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);

        $status = $this->move('/' . self::FOLDER . '/missing.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(404, $status);
        $this->assertFixturesUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/renamed.txt'));
    }

    public function testTreeMoveToMissingDestinationFolderIsNotFound(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $tree = new \Pimcore\Model\Asset\WebDAV\Tree(new \Pimcore\Model\Asset\WebDAV\Folder(\Pimcore\Model\Asset::getById(1)));

        $thrown = null;
        try {
            $tree->move(self::FOLDER . '/source.txt', self::FOLDER . '/missing-folder/source.txt');
        } catch (\Sabre\DAV\Exception\NotFound $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Sabre\DAV\Exception\NotFound::class, $thrown);
        $this->assertSourceUnchanged();
    }

    public function testViewOnlyUserCannotRenameFolder(): void
    {
        $status = $this->move('/' . self::FOLDER . '/sub', '/' . self::FOLDER . '/sub-renamed');

        $this->assertSame(403, $status);
        $this->assertNotNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub'));
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub-renamed'));
    }

    public function testUnauthenticatedMoveIsForbidden(): void
    {
        $this->authenticate(null);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(403, $status);
        $this->assertFixturesUnchanged();
    }

    public function testUserWithFullWorkspaceCanRename(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt');

        $this->assertSame(201, $status);
        $renamed = \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/renamed.txt');
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $renamed);
        $this->assertSame($this->source->getId(), $renamed->getId());
        $this->assertSame(self::SOURCE_DATA, $renamed->getData());
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/source.txt'));
    }

    public function testUserWithFullWorkspaceCanOverwrite(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/existing.txt');

        $this->assertSame(204, $status);
        $existing = \Pimcore\Model\Asset::getById($this->existing->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $existing);
        $this->assertSame(self::SOURCE_DATA, $existing->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($this->source->getId(), ['force' => true]));
    }

    public function testControllerRegistersMoveGuardPlugin(): void
    {
        $server = $this->createServer();

        $this->assertInstanceOf(\Pimcore\Model\Asset\WebDAV\MoveGuardPlugin::class, $server->getPlugin('pimcore-asset-move-guard'));
    }

    public function testControlRefusedOverwriteOfDeleteLoggedPathLeavesNoTrace(): void
    {
        $ghostId = $this->deleteGhostAsAdmin();
        $this->grantWorkspace(['view' => true, 'list' => true, 'rename' => true, 'publish' => true, 'create' => true]);

        $this->assertSame(403, $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt'));

        $this->assertSourceUnchanged();
        $this->assertNull(\Pimcore\Model\Asset::getById($ghostId, ['force' => true]));
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/ghost.txt'));
    }

    public function testExistingDestinationFolderSurvivesMoveWithoutRenameRight(): void
    {
        $this->grantWorkspace(['view' => true, 'list' => true, 'create' => true, 'publish' => true, 'delete' => true]);
        $child = \Pimcore\Model\Asset::create($this->subfolder->getId(), ['filename' => 'child.txt', 'data' => 'pd-sec-webdav-child']);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub');

        $this->assertSame(403, $status);
        $this->assertSourceUnchanged();
        $this->assertInstanceOf(\Pimcore\Model\Asset\Folder::class, \Pimcore\Model\Asset::getById($this->subfolder->getId(), ['force' => true]));
        $survivingChild = \Pimcore\Model\Asset::getById($child->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $survivingChild);
        $this->assertSame('/' . self::FOLDER . '/sub/child.txt', $survivingChild->getRealFullPath());
    }

    public function testCrossFolderMoveToTakenPathIsRefusedBeforeDestinationIsDeleted(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $occupant = \Pimcore\Model\Asset::create($this->subfolder->getId(), ['filename' => 'source.txt', 'data' => 'pd-sec-webdav-occupant']);
        $destination = \Pimcore\Model\Asset::create($this->subfolder->getId(), ['filename' => 'other.txt', 'data' => 'pd-sec-webdav-destination']);

        $status = $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/other.txt', unexpectedAsServerError: true);

        $this->assertSame(409, $status);
        $this->assertSourceUnchanged();
        $survivingDestination = \Pimcore\Model\Asset::getById($destination->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $survivingDestination, 'Destination asset was deleted.');
        $this->assertSame('pd-sec-webdav-destination', $survivingDestination->getData());
        $survivingOccupant = \Pimcore\Model\Asset::getById($occupant->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $survivingOccupant);
        $this->assertSame('pd-sec-webdav-occupant', $survivingOccupant->getData());
    }

    public function testOverwriteWithoutRenameRightSucceedsWhenTheDeleteLogEntryIsGone(): void
    {
        $this->grantWorkspace(['view' => true, 'list' => true, 'create' => true, 'publish' => true, 'delete' => true]);
        $destinationId = $this->existing->getId();

        $status = $this->request(
            'MOVE',
            '/' . self::FOLDER . '/source.txt',
            '/' . self::FOLDER . '/existing.txt',
            afterDestinationDeleted: static function (): void {
                file_put_contents(\Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile(), 'pd-sec-undecodable-delete-log');
            },
        );

        $this->assertSame(204, $status);
        $this->assertNull(\Pimcore\Model\Asset::getById($destinationId, ['force' => true]));
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/source.txt'));
        $result = \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/existing.txt');
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $result);
        $this->assertSame($this->source->getId(), $result->getId());
        $this->assertSame(self::SOURCE_DATA, $result->getData());
    }

    public function testCrossFolderMoveOntoDestinationOfAnotherNameIsRefusedBeforeItIsDeleted(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $destination = \Pimcore\Model\Asset::create($this->subfolder->getId(), ['filename' => 'other.txt', 'data' => 'pd-sec-webdav-destination']);

        $status = $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/other.txt', unexpectedAsServerError: true);

        $this->assertSame(409, $status);
        $this->assertSourceUnchanged();
        $survivingDestination = \Pimcore\Model\Asset::getById($destination->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $survivingDestination, 'Destination asset was deleted.');
        $this->assertSame('/' . self::FOLDER . '/sub/other.txt', $survivingDestination->getRealFullPath());
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub/source.txt'));
    }

    public function testControlCrossFolderOverwriteOfSameNamedAssetStillWorks(): void
    {
        $this->grantWorkspace(self::ALL_RIGHTS);
        $occupant = \Pimcore\Model\Asset::create($this->subfolder->getId(), ['filename' => 'source.txt', 'data' => 'pd-sec-webdav-occupant']);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/sub/source.txt');

        $this->assertSame(204, $status);
        $moved = \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/sub/source.txt');
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $moved);
        $this->assertSame($this->source->getId(), $moved->getId());
        $this->assertSame(self::SOURCE_DATA, $moved->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($occupant->getId(), ['force' => true]));
    }

    private function move(string $sourcePath, string $destinationPath): int
    {
        return $this->request('MOVE', $sourcePath, $destinationPath);
    }

    private function createServer(): \Sabre\DAV\Server
    {
        $controller = new \Pimcore\Bundle\CoreBundle\Controller\WebDavController();
        $controller->setContainer(\Pimcore::getContainer());
        $server = (new \ReflectionMethod($controller, 'createServer'))->invoke($controller);
        \assert($server instanceof \Sabre\DAV\Server);

        return $server;
    }

    private function request(string $method, string $path, ?string $destinationPath = null, bool $unexpectedAsServerError = false, ?\Closure $afterDestinationDeleted = null): int
    {
        $server = method_exists(\Pimcore\Bundle\CoreBundle\Controller\WebDavController::class, 'createServer') ? $this->createServer() : $this->createPlainServer();
        if (null !== $afterDestinationDeleted) {
            $server->on('afterUnbind', $afterDestinationDeleted);
        }

        $baseUri = $server->getBaseUri();
        $headers = null === $destinationPath ? [] : [
            'Destination' => $baseUri . ltrim($destinationPath, '/'),
            'Overwrite' => 'T',
        ];
        $request = new \Sabre\HTTP\Request($method, $baseUri . ltrim($path, '/'), $headers);
        $request->setBaseUrl($baseUri);
        $response = new \Sabre\HTTP\Response();

        try {
            $server->invokeMethod($request, $response, false);
        } catch (\Sabre\DAV\Exception $e) {
            return $e->getHTTPCode();
        } catch (\Throwable $e) {
            if ($unexpectedAsServerError) {
                return 500;
            }

            self::fail($method . ' threw ' . get_class($e) . ': ' . $e->getMessage());
        }

        return $response->getStatus();
    }

    private function createPlainServer(): \Sabre\DAV\Server
    {
        $tree = new \Pimcore\Model\Asset\WebDAV\Tree(new \Pimcore\Model\Asset\WebDAV\Folder(\Pimcore\Model\Asset::getById(1)));
        $server = new \Sabre\DAV\Server($tree);
        $server->setBaseUri(self::BASE_URI);

        return $server;
    }

    private function deleteGhostAsAdmin(): int
    {
        $ghost = $this->createTextAsset('ghost.txt', self::GHOST_DATA);
        $this->authenticate($this->admin);

        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->assertNull(\Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]));

        return $ghost->getId();
    }

    private function assertFixturesUnchanged(): void
    {
        $this->assertSourceUnchanged();

        $existing = \Pimcore\Model\Asset::getById($this->existing->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $existing, 'Existing asset was deleted.');
        $this->assertSame(self::EXISTING_DATA, $existing->getData());
    }

    private function createDeepFolder(): \Pimcore\Model\Asset\Folder
    {
        $parent = $this->folder;
        foreach ([255, 255, 235] as $length) {
            $parent = $this->createAssetFolder(parentId: $parent->getId(), filename: str_repeat('d', $length));
        }

        return $parent;
    }

    private function reloadedSource(): \Pimcore\Model\Asset
    {
        $source = \Pimcore\Model\Asset::getById($this->source->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $source);

        return $source;
    }

    private function assertSourceUnchanged(): void
    {
        $source = \Pimcore\Model\Asset::getById($this->source->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $source, 'Source asset was deleted.');
        $this->assertSame('/' . self::FOLDER . '/source.txt', $source->getRealFullPath());
        $this->assertSame(self::SOURCE_DATA, $source->getData());
    }

    /**
     * @param array<string, bool> $rights
     */
    private function grantWorkspace(array $rights): void
    {
        $this->grant([$this->workspace($this->folder, $rights)]);
    }

    /**
     * @param list<\Pimcore\Model\User\Workspace\Asset> $workspaces
     */
    private function grant(array $workspaces): void
    {
        $this->user->setWorkspacesAsset($workspaces);
        $this->user->save();
        $this->authenticate($this->user);
    }

    /**
     * @param array<string, bool> $rights
     */
    private function workspace(\Pimcore\Model\Asset $asset, array $rights): \Pimcore\Model\User\Workspace\Asset
    {
        $workspace = new \Pimcore\Model\User\Workspace\Asset();
        $workspace->setCid($asset->getId());
        $workspace->setCpath($asset->getRealFullPath());
        foreach ($rights as $right => $granted) {
            $workspace->{'set' . ucfirst($right)}($granted);
        }

        return $workspace;
    }

    private function createTextAsset(string $filename, string $data): \Pimcore\Model\Asset
    {
        return \Pimcore\Model\Asset::create($this->folder->getId(), [
            'filename' => $filename,
            'data' => $data,
        ]);
    }

    private function removeFixtures(): void
    {
        try {
            $this->deleteUserByName(self::USERNAME);
        } finally {
            try {
                $this->deleteUserByName(self::ADMIN_USERNAME);
            } finally {
                try {
                    $this->deleteAssetByPath('/' . self::FOLDER);
                } finally {
                    $this->pruneDeleteLog();
                }
            }
        }
    }

    private function pruneDeleteLog(): void
    {
        $prefix = '/' . self::FOLDER . '/';
        $log = array_filter(
            \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog(),
            static fn (string|int $path): bool => !str_starts_with((string) $path, $prefix),
            ARRAY_FILTER_USE_KEY,
        );
        \Pimcore\Model\Asset\WebDAV\Service::saveDeleteLog($log);
    }
}
