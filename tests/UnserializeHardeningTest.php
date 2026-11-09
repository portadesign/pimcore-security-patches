<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-55220')]
final class UnserializeHardeningTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\RejectedSerializedPayloads;

    private const FIXTURE_FOLDER = 'pd-sec-unserialize';

    /**
     * @var list<\Closure>
     */
    private array $cleanups = [];

    /**
     * @var array<string, mixed>
     */
    private array $originalSystemConfiguration = [];

    protected function setUp(): void
    {
        $this->resetCanary();
        \Pimcore\Model\Version::disable();
        $this->originalSystemConfiguration = \Pimcore\Config::getSystemConfiguration() ?? [];
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->cleanups) as $cleanup) {
            $cleanup();
        }

        $this->cleanups = [];
        \Pimcore\Config::setSystemConfiguration($this->originalSystemConfiguration);
        $this->deleteAssetByPath('/' . self::FIXTURE_FOLDER);
        \Pimcore\Model\Version::enable();
        $this->resetCanary();
    }

    /**
     * @return array<string, array{array<int, string>|bool}>
     */
    public static function denyAllProvider(): array
    {
        return [
            'empty allowlist' => [[]],
            'boolean false' => [false],
        ];
    }

    /**
     * @param array<int, string>|bool $allowedClasses
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('denyAllProvider')]
    public function testSerializeDoesNotInstantiateClassOutsideAllowlist(array|bool $allowedClasses): void
    {
        $result = \Pimcore\Tool\Serialize::unserialize($this->serialized(fn (): mixed => $this->canary()), $allowedClasses);

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran during unserialize().');
    }

    public function testSerializeKeepsOnlyAllowlistedClasses(): void
    {
        $payload = $this->serialized(fn (): mixed => ['allowed' => $this->canary(), 'foreign' => new \stdClass()]);

        $result = \Pimcore\Tool\Serialize::unserialize($payload, [\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class]);

        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class, $result['allowed']);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result['foreign']);
    }

    public function testControlSerializeKeepsDefaultBehaviourWithoutAllowlist(): void
    {
        $result = \Pimcore\Tool\Serialize::unserialize(serialize(['a' => new \stdClass()]));

        $this->assertInstanceOf(\stdClass::class, $result['a']);
    }

    public function testControlSerializeReturnsEmptyInputUnchanged(): void
    {
        $this->assertNull(\Pimcore\Tool\Serialize::unserialize(null));
        $this->assertSame('', \Pimcore\Tool\Serialize::unserialize(''));
    }

    public function testHotspotimageDoesNotInstantiateForeignClassInMetadata(): void
    {
        $field = $this->hotspotField();
        $payload = $this->serialized(fn (): mixed => ['hotspots' => [['name' => 'spot', 'data' => [$this->canary()]]]]);

        $value = $field->getDataFromResource(['hs__image' => $this->fixtureImageId(), 'hs__hotspots' => $payload]);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Hotspotimage::class, $value);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $value->getHotspots()[0]['data'][0]);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Hotspotimage metadata.');
    }

    public function testHotspotimageDoesNotInstantiateForeignClassAtTopLevel(): void
    {
        $field = $this->hotspotField();
        $payload = $this->serialized(fn (): mixed => $this->canary());

        try {
            $field->getDataFromResource(['hs__image' => $this->fixtureImageId(), 'hs__hotspots' => $payload]);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Hotspotimage metadata.');
    }

    public function testControlHotspotimageKeepsLegitimateMarkerItems(): void
    {
        $field = $this->hotspotField();
        $item = new \Pimcore\Model\Element\Data\MarkerHotspotItem(['name' => 'label', 'type' => 'textfield', 'value' => 'v']);
        $payload = $this->serialized(fn (): mixed => ['hotspots' => [['name' => 'spot', 'data' => [$item]]]]);

        $value = $field->getDataFromResource(['hs__image' => $this->fixtureImageId(), 'hs__hotspots' => $payload]);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Hotspotimage::class, $value);
        $restored = $value->getHotspots()[0]['data'][0];
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $restored);
        $this->assertSame('v', $restored->getValue());
    }

    public function testImageGalleryNeverInstantiatesForeignClassInHotspotColumn(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\ImageGallery();
        $field->setName('gal');

        try {
            $field->getDataFromResource(['gal__images' => ',1,', 'gal__hotspots' => $this->serialized(fn (): mixed => [$this->canary()])]);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading ImageGallery data.');
    }

    public function testControlImageGalleryReloadKeepsHotspotItems(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\ImageGallery();
        $field->setName('gal');
        $gallery = new \Pimcore\Model\DataObject\Data\ImageGallery([
            new \Pimcore\Model\DataObject\Data\Hotspotimage(
                $this->createImageAsset(),
                [['name' => 'h', 'data' => [$this->markerItem()]]],
                [],
                [],
            ),
        ]);

        $loaded = $field->getDataFromResource($field->getDataForResource($gallery));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\ImageGallery::class, $loaded);
        $this->assertCount(1, $loaded->getItems());
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loaded->getItems()[0]->getHotspots()[0]['data'][0]);
    }

    public function testVideoNeverInstantiatesForeignClassInStoredValue(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Video();

        try {
            $field->getDataFromResource($this->serialized(fn (): mixed => $this->canary()));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Video data.');
    }

    public function testVideoNeverInstantiatesForeignClassNestedInStoredValue(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Video();
        $payload = $this->serialized(fn (): mixed => [
            'type' => 'youtube',
            'data' => 'pd-sec-video',
            'poster' => null,
            'title' => $this->canary(),
            'description' => null,
        ]);

        try {
            $field->getDataFromResource($payload);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Video data.');
    }

    public function testControlVideoReloadKeepsValues(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Video();
        $video = new \Pimcore\Model\DataObject\Data\Video();
        $video->setType('youtube');
        $video->setData('pd-sec-video');
        $video->setTitle('pd-sec-title');

        $loaded = $field->getDataFromResource($field->getDataForResource($video));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Video::class, $loaded);
        $this->assertSame(['youtube', 'pd-sec-video', 'pd-sec-title'], [$loaded->getType(), $loaded->getData(), $loaded->getTitle()]);
    }

    public function testBlockDoesNotInstantiateForeignClass(): void
    {
        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('blk');

        try {
            $block->getDataFromResource(
                $this->serialized(fn (): mixed => [['range' => ['name' => 'range', 'type' => 'daterange', 'data' => [$this->canary()]]]]),
                null,
                ['owner' => new \Pimcore\Model\DataObject\Concrete(), 'fieldname' => 'blk'],
            );
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Block data.');
    }

    public function testControlBlockReloadKeepsDateAndHotspotimage(): void
    {
        $image = $this->createImageAsset();
        $date = new \Pimcore\Model\DataObject\ClassDefinition\Data\Date();
        $date->setName('day');
        $hotspot = new \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage();
        $hotspot->setName('hs');
        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('blk');
        $block->setChildren([$date, $hotspot]);
        $params = ['owner' => new \Pimcore\Model\DataObject\Concrete(), 'fieldname' => 'blk'];
        $hotspotImage = new \Pimcore\Model\DataObject\Data\Hotspotimage(
            $image,
            [['name' => 'h', 'data' => [$this->markerItem()]]],
            [['name' => 'm', 'data' => [$this->markerItem()]]],
            [],
        );

        $stored = $block->getDataForResource([[
            'day' => new \Pimcore\Model\DataObject\Data\BlockElement('day', 'date', \Carbon\Carbon::parse('2024-01-03')),
            'hs' => new \Pimcore\Model\DataObject\Data\BlockElement('hs', 'hotspotimage', $hotspotImage),
        ]], null, $params);
        $loaded = $block->getDataFromResource($stored, null, $params);

        $this->assertSame('2024-01-03', $loaded[0]['day']->getData()->format('Y-m-d'));
        $loadedHotspot = $loaded[0]['hs']->getData();
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loadedHotspot->getHotspots()[0]['data'][0]);
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loadedHotspot->getMarker()[0]['data'][0]);
    }

    public function testSiteDomainsDoNotInstantiateForeignClass(): void
    {
        $site = new \Pimcore\Model\Site();

        try {
            $site->setDomains($this->serialized(fn (): mixed => ['a.example.com', $this->canary()]));
        } catch (\TypeError) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site::setDomains().');
    }

    public function testControlSiteDomainsKeepSerializedDomainList(): void
    {
        $site = new \Pimcore\Model\Site();

        $site->setDomains(serialize(['a.example.com', '*.example.org']));

        $this->assertSame(['a.example.com', '*.example.org'], $site->getDomains());
    }

    public function testSiteLocalizedErrorDocumentsDoNotInstantiateForeignClass(): void
    {
        $site = new \Pimcore\Model\Site();

        $site->setLocalizedErrorDocuments($this->serialized(fn (): mixed => ['en' => '/error', 'cs' => $this->canary()]));

        $this->assertSame('/error', $site->getLocalizedErrorDocuments()['en']);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $site->getLocalizedErrorDocuments()['cs']);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site::setLocalizedErrorDocuments().');
    }

    public function testControlSiteLocalizedErrorDocumentsKeepSerializedMap(): void
    {
        $site = new \Pimcore\Model\Site();

        $site->setLocalizedErrorDocuments(serialize(['en' => '/error', 'cs' => '/chyba']));

        $this->assertSame(['en' => '/error', 'cs' => '/chyba'], $site->getLocalizedErrorDocuments());
    }

    public function testSiteWildcardLookupDoesNotInstantiateForeignClassFromDatabase(): void
    {
        $this->insertSiteRow($this->serialized(fn (): mixed => ['*.pd-sec.example', $this->canary()]));

        try {
            (new \Pimcore\Model\Site())->getDao()->getByDomain('shop.pd-sec.example');
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Site\\Dao::getByDomain().');
    }

    public function testControlSiteWildcardLookupStillResolvesLegitimateWildcardDomain(): void
    {
        $siteId = $this->insertSiteRow(serialize(['*.pd-sec.example']));

        $site = new \Pimcore\Model\Site();
        $site->getDao()->getByDomain('shop.pd-sec.example');

        $this->assertSame($siteId, $site->getId());
    }

    /**
     * @return array<string, array{bool}>
     */
    public static function foreignTmpStorePayloadProvider(): array
    {
        return [
            'top level object' => [false],
            'nested in array' => [true],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignTmpStorePayloadProvider')]
    public function testTmpStoreRejectsForeignClass(bool $nested): void
    {
        $data = $nested ? ['wrapper' => ['inner' => $this->canary()]] : $this->canary();
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, $data);
        $this->resetCanary();

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertNull($item);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in TmpStore\\Dao::getById().');
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('rejectedSerializedPayloadProvider')]
    public function testTmpStoreRejectsPayloadNamingClassOutsideAllowlist(string $payload): void
    {
        $id = $this->storeSerializedPayload($payload);

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertNull($item);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in TmpStore\\Dao::getById().');
    }

    public function testControlTmpStoreReturnsPlainArray(): void
    {
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, ['a' => 1, 'b' => ['c' => 'd']]);

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertSame(['a' => 1, 'b' => ['c' => 'd']], $item->getData());
    }

    public function testControlTmpStoreReturnsAllowlistedImageThumbnailConfig(): void
    {
        $id = $this->tmpStoreId();
        $config = new \Pimcore\Model\Asset\Image\Thumbnail\Config();
        $config->setName('pd-sec-thumbnail');
        \Pimcore\Model\Tool\TmpStore::set($id, $config);

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $item->getData());
        $this->assertSame('pd-sec-thumbnail', $item->getData()->getName());
    }

    public function testControlTmpStoreReturnsVideoThumbnailProcessor(): void
    {
        $config = new \Pimcore\Model\Asset\Video\Thumbnail\Config();
        $config->setName('pd-sec-video-thumbnail');
        $processor = new \Pimcore\Model\Asset\Video\Thumbnail\Processor();
        $processor->setProcessId('pd-sec-' . bin2hex(random_bytes(6)));
        $processor->setAssetId(1);
        $processor->setConfig($config);
        (new \ReflectionProperty($processor, 'queue'))->setValue($processor, [new \Pimcore\Video\Adapter\Ffmpeg()]);
        $id = 'video-job-' . $processor->getProcessId();
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Tool\TmpStore::delete($id);
        };

        $processor->save();
        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $restored = $item->getData();
        $this->assertInstanceOf(\Pimcore\Model\Asset\Video\Thumbnail\Processor::class, $restored);
        $this->assertSame('pd-sec-video-thumbnail', $restored->getConfig()->getName());
        $this->assertInstanceOf(\Pimcore\Video\Adapter\Ffmpeg::class, (new \ReflectionProperty($restored, 'queue'))->getValue($restored)[0]);
    }

    /**
     * @return array<string, array{\Closure(string): string}>
     */
    public static function caseVariantProvider(): array
    {
        return [
            'upper-case class name' => [static fn (string $name): string => strtoupper($name)],
            'lower-case class name' => [static fn (string $name): string => strtolower($name)],
        ];
    }

    /**
     * @param \Closure(string): string $variant
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('caseVariantProvider')]
    public function testControlTmpStoreAcceptsCaseVariantOfAllowlistedClass(\Closure $variant): void
    {
        $config = new \Pimcore\Model\Asset\Image\Thumbnail\Config();
        $config->setName('pd-sec-thumbnail');
        $id = $this->storeSerializedPayload($this->withClassNameVariant(serialize($config), $variant));

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $item->getData());
        $this->assertSame('pd-sec-thumbnail', $item->getData()->getName());
    }

    public function testControlTmpStoreAcceptsClassAddedThroughConfiguration(): void
    {
        $this->configureTmpStoreAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class]);
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, $this->canary());

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class, $item->getData());
    }

    public function testControlTmpStoreKeepsBuiltInClassesWhenConfigurationAddsOthers(): void
    {
        $this->configureTmpStoreAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class]);
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, new \Pimcore\Model\Asset\Image\Thumbnail\Config());

        $item = \Pimcore\Model\Tool\TmpStore::get($id);

        $this->assertInstanceOf(\Pimcore\Model\Tool\TmpStore::class, $item);
        $this->assertInstanceOf(\Pimcore\Model\Asset\Image\Thumbnail\Config::class, $item->getData());
    }

    public function testTmpStoreRejectsClassNotAddedThroughConfiguration(): void
    {
        $this->configureTmpStoreAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::class]);
        $id = $this->tmpStoreId();
        \Pimcore\Model\Tool\TmpStore::set($id, new \stdClass());

        $this->assertNull(\Pimcore\Model\Tool\TmpStore::get($id));
    }

    public function testSubtypesInstantiatesSubclassOfBaseTypeButNotUnrelatedClass(): void
    {
        $payload = serialize([
            'project' => new \Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectMockup(1, [], []),
            'foreign' => $this->canary(),
        ]);
        $this->resetCanary();

        $result = \Pimcore\Tool\Serialize::unserializeSubtypes($payload, [\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup::class]);

        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\P2ProjectMockup::class, $result['project']);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result['foreign']);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in unserializeSubtypes().');
    }

    public function testSubtypesAcceptsExtraClassesBesideBaseTypes(): void
    {
        $payload = serialize([new \DateTime('2024-01-01'), new \stdClass()]);

        $result = \Pimcore\Tool\Serialize::unserializeSubtypes($payload, [\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup::class], [\DateTime::class]);

        $this->assertInstanceOf(\DateTime::class, $result[0]);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result[1]);
    }

    public function testSubtypesNeverTriggersAutoloadForClassNamesWithOddCharacters(): void
    {
        $requested = [];
        $recorder = static function (string $class) use (&$requested): void {
            $requested[] = $class;
        };
        $odd = '9PdSecOdd\\Class';
        $payload = 'a:1:{i:0;O:' . strlen($odd) . ':"' . $odd . '":0:{}}';

        spl_autoload_register($recorder, true, true);
        try {
            $result = \Pimcore\Tool\Serialize::unserializeSubtypes($payload, [\Pimcore\Bundle\EcommerceFrameworkBundle\Model\DefaultMockup::class]);
        } finally {
            spl_autoload_unregister($recorder);
        }

        $this->assertSame([], array_values(array_filter($requested, static fn (string $class): bool => str_contains($class, '9PdSecOdd'))));
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result[0]);
    }

    private function hotspotField(): \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage();
        $field->setName('hs');

        return $field;
    }

    private function fixtureImageId(): int
    {
        return $this->fixtureFolder()->getId();
    }

    private function fixtureFolder(): \Pimcore\Model\Asset\Folder
    {
        $existing = \Pimcore\Model\Asset::getByPath('/' . self::FIXTURE_FOLDER);
        if ($existing instanceof \Pimcore\Model\Asset\Folder) {
            return $existing;
        }

        return $this->createAssetFolder(parentId: 1, filename: self::FIXTURE_FOLDER);
    }

    private function createImageAsset(): \Pimcore\Model\Asset\Image
    {
        $image = \Pimcore\Model\Asset::create($this->fixtureFolder()->getId(), [
            'filename' => 'pixel.png',
            'data' => (string) base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='),
        ]);
        self::assertInstanceOf(\Pimcore\Model\Asset\Image::class, $image);

        return $image;
    }

    private function markerItem(): \Pimcore\Model\Element\Data\MarkerHotspotItem
    {
        return new \Pimcore\Model\Element\Data\MarkerHotspotItem(['name' => 'label', 'type' => 'input', 'value' => 'v']);
    }

    private function tmpStoreId(): string
    {
        $id = 'pd-sec-' . bin2hex(random_bytes(6));
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Tool\TmpStore::delete($id);
        };

        return $id;
    }

    private function storeSerializedPayload(string $payload): string
    {
        $id = $this->tmpStoreId();
        \Pimcore\Db::get()->insert('tmp_store', [
            'id' => $id,
            'data' => $payload,
            'tag' => null,
            'date' => time(),
            'expiryDate' => time() + 300,
            'serialized' => 1,
        ]);

        return $id;
    }

    /**
     * @param \Closure(string): string $variant
     */
    private function withClassNameVariant(string $serialized, \Closure $variant): string
    {
        return (string) preg_replace_callback(
            '/^O:(\d+):"([^"]+)"/',
            static fn (array $match): string => 'O:' . $match[1] . ':"' . $variant($match[2]) . '"',
            $serialized,
        );
    }

    /**
     * @param list<string> $classes
     */
    private function configureTmpStoreAllowedClasses(array $classes): void
    {
        \Pimcore\Config::setSystemConfiguration(['unserialize_allowed_classes' => $classes], 'tmp_store');
    }

    private function insertSiteRow(string $serializedDomains): int
    {
        $db = \Pimcore\Db::get();
        $db->insert('sites', ['domains' => $serializedDomains]);
        $siteId = (int) $db->lastInsertId();
        $this->cleanups[] = static function () use ($siteId): void {
            \Pimcore\Db::get()->delete('sites', ['id' => $siteId]);
        };

        return $siteId;
    }

    private function canary(): object
    {
        return new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary();
    }

    private function serialized(\Closure $factory): string
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized($factory);
    }

    private function resetCanary(): void
    {
        gc_collect_cycles();
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();
    }

    private function canaryExecutions(): int
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions;
    }
}
