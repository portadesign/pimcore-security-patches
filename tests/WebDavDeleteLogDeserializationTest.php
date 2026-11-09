<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45162')]
final class WebDavDeleteLogDeserializationTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P4WebDavSubprocess;

    private const USERNAME = 'pd-sec-deletelog-user';

    private const ADMIN_USERNAME = 'pd-sec-deletelog-admin';

    private const FOLDER = 'pd-sec-deletelog';

    private const SOURCE_DATA = 'pd-sec-deletelog-source-data';

    private const GHOST_DATA = 'pd-sec-deletelog-ghost-data';

    private const BASE_URI = '/asset/webdav/';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $admin;

    private \Pimcore\Model\Asset\Folder $folder;

    private \Pimcore\Model\Asset $source;

    /**
     * @var array{0: array<int, mixed>, 1: array<string, int>}|null
     */
    private ?array $originalFactoryState = null;

    protected function setUp(): void
    {
        $this->removeFixtures();
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();

        $this->folder = $this->createAssetFolder(parentId: 1, filename: self::FOLDER);
        $this->source = \Pimcore\Model\Asset::create($this->folder->getId(), ['filename' => 'source.txt', 'data' => self::SOURCE_DATA]);

        $this->admin = $this->createUser(self::ADMIN_USERNAME, true);
        $this->user = $this->createUser(self::USERNAME, false);

        $workspace = new \Pimcore\Model\User\Workspace\Asset();
        $workspace->setCid($this->folder->getId());
        $workspace->setCpath($this->folder->getRealFullPath());
        foreach (['view', 'list', 'rename', 'publish', 'create', 'delete', 'settings'] as $right) {
            $workspace->{'set' . ucfirst($right)}(true);
        }
        $this->user->setWorkspacesAsset([$workspace]);
        $this->user->save();
        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->restoreAssetClassOverride();
        $this->rollBackOpenTransactions();
        $this->removeFixtures();
    }

    public function testCanaryInDeleteLogIsNotUnserializedAndMoveBehavesAsForMissingDestination(): void
    {
        $payload = \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized(
            static fn (): \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary => new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary(),
        );
        \Pimcore\Model\Asset\WebDAV\Service::saveDeleteLog([
            '/' . self::FOLDER . '/ghost.txt' => ['id' => 0, 'timestamp' => time(), 'data' => $payload],
        ]);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(0, \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions, 'The delete log payload was unserialized.');
        $this->assertSame(201, $status);
        $renamed = \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/ghost.txt');
        $this->assertSame($this->source->getId(), $renamed?->getId());
        $this->assertSame(self::SOURCE_DATA, $renamed->getData());
        $this->assertNull(\Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/source.txt'));
    }

    public function testControlLegitimateDeleteLogEntryIsRestored(): void
    {
        $ghost = \Pimcore\Model\Asset::create($this->folder->getId(), ['filename' => 'ghost.txt', 'data' => self::GHOST_DATA]);
        $this->authenticate($this->admin);
        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->authenticate($this->user);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(201, $status);
        $restored = \Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]);
        $this->assertSame('/' . self::FOLDER . '/ghost.txt', $restored?->getRealFullPath());
        $this->assertSame(self::SOURCE_DATA, $restored->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($this->source->getId(), ['force' => true]));
    }

    public function testDeleteLoggedAssetOfOverriddenClassIsRestored(): void
    {
        $this->overrideAssetClass(\Pimcore\Model\Asset\Text::class, \Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class);
        $ghost = \Pimcore\Model\Asset::create($this->folder->getId(), ['filename' => 'ghost.txt', 'data' => self::GHOST_DATA]);
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class, $ghost);
        $this->authenticate($this->admin);
        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->authenticate($this->user);

        $status = $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(201, $status);
        $restored = \Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]);
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class, $restored);
        $this->assertSame('/' . self::FOLDER . '/ghost.txt', $restored->getRealFullPath());
        $this->assertSame(self::SOURCE_DATA, $restored->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($this->source->getId(), ['force' => true]));
    }

    public function testDeleteLogEntryOfAnOverrideThatIsNoLongerConfiguredIsDropped(): void
    {
        $this->overrideAssetClass(\Pimcore\Model\Asset\Text::class, \Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class);
        $ghost = \Pimcore\Model\Asset::create($this->folder->getId(), ['filename' => 'ghost.txt', 'data' => self::GHOST_DATA]);
        $this->authenticate($this->admin);
        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->restoreAssetClassOverride();
        $this->authenticate($this->user);

        $this->assertArrayNotHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->assertSame(201, $this->move('/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertNull(\Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]));
        $this->assertSame($this->source->getId(), \Pimcore\Model\Asset::getByPath('/' . self::FOLDER . '/ghost.txt')?->getId());
    }

    private function move(string $sourcePath, string $destinationPath): int
    {
        return $this->request('MOVE', $sourcePath, $destinationPath);
    }

    private function request(string $method, string $path, ?string $destinationPath = null): int
    {
        $tree = new \Pimcore\Model\Asset\WebDAV\Tree(new \Pimcore\Model\Asset\WebDAV\Folder(\Pimcore\Model\Asset::getById(1)));
        $server = new \Sabre\DAV\Server($tree);
        $server->setBaseUri(self::BASE_URI);

        $headers = null === $destinationPath ? [] : [
            'Destination' => self::BASE_URI . ltrim($destinationPath, '/'),
            'Overwrite' => 'T',
        ];
        $request = new \Sabre\HTTP\Request($method, self::BASE_URI . ltrim($path, '/'), $headers);
        $request->setBaseUrl(self::BASE_URI);
        $response = new \Sabre\HTTP\Response();

        try {
            $server->invokeMethod($request, $response, false);
        } catch (\Sabre\DAV\Exception $e) {
            return $e->getHTTPCode();
        } catch (\Throwable $e) {
            return 500;
        }

        return $response->getStatus();
    }

    private function overrideAssetClass(string $source, string $target): void
    {
        $factory = \Pimcore::getContainer()->get('pimcore.model.factory');
        $loaders = new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaders');
        $cache = new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaderCache');
        $this->originalFactoryState ??= [$loaders->getValue($factory), $cache->getValue($factory)];

        $factory->addLoader(new \Pimcore\Loader\ImplementationLoader\ClassMapLoader([$source => $target]));
        $cache->setValue($factory, []);
    }

    private function restoreAssetClassOverride(): void
    {
        if (null === $this->originalFactoryState) {
            return;
        }

        $factory = \Pimcore::getContainer()->get('pimcore.model.factory');
        (new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaders'))->setValue($factory, $this->originalFactoryState[0]);
        (new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaderCache'))->setValue($factory, $this->originalFactoryState[1]);
        $this->originalFactoryState = null;
    }

    private function createUser(string $name, bool $admin): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => $admin,
        ]);
        $user->setPermissions($admin ? [] : ['assets']);
        $user->save();

        return $user;
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

        if ([] === $log) {
            @unlink(\Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile());
        }
    }
}
