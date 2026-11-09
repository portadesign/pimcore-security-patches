<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45162')]
final class UnserializeRemainingPathsTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;

    private const ADMIN_USERNAME = 'pd-sec-unserialize-remaining-admin';

    private const DASHBOARD_USERNAME = 'pd-sec-unserialize-remaining-dashboard';

    private const FOLDER = 'pd-sec-unserialize-remaining';

    private const SESSION_ID = 'pd-sec-unserialize-remaining-session';

    private const ERROR_LOG_URI = '/pd-sec-unserialize-remaining-error-log';

    private const BASE_URI = '/asset/webdav/';

    private const SOURCE_DATA = 'pd-sec-remaining-source-data';

    private const GHOST_DATA = 'pd-sec-remaining-ghost-data';

    private ?string $originalDeleteLog = null;

    /**
     * @var array{0: array<int, mixed>, 1: array<string, int>}|null
     */
    private ?array $originalFactoryState = null;

    /**
     * @var list<int>
     */
    private array $sessionAssets = [];

    private ?string $originalDashboard = null;

    private ?\Pimcore\Model\User $dashboardUser = null;

    private ?\Pimcore\Model\Asset\Folder $folder = null;

    protected function setUp(): void
    {
        $this->resetCanary();
        $logFile = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile();
        $this->originalDeleteLog = is_file($logFile) ? (string) file_get_contents($logFile) : null;
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->restoreAssetClassOverride();
        $this->restoreDeleteLog();
        $this->restoreDashboard();
        $this->deleteErrorLogRow();
        $this->removeSessionRows();
        $this->deleteUserByName(self::ADMIN_USERNAME);
        $this->deleteAssetByPath('/' . self::FOLDER);
        $this->resetCanary();
    }

    public function testDeleteLogWithTopLevelForeignObjectIsEmptyAndNotInstantiated(): void
    {
        $this->writeDeleteLog(serialize($this->canary()));
        $this->resetCanary();

        $this->assertSame([], \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the WebDAV delete log.');
    }

    public function testDeleteLogEntryWithNestedForeignObjectIsNotInstantiated(): void
    {
        $this->writeDeleteLog($this->serialized(fn (): mixed => [
            '/pd-sec-remaining/a.txt' => ['id' => 1, 'timestamp' => time(), 'data' => 'x', 'extra' => $this->canary()],
        ]));

        \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the WebDAV delete log.');
    }

    public function testDeleteLogEntryWithForeignObjectAsDeletedAssetIsDropped(): void
    {
        $this->writeDeleteLog($this->serialized(fn (): mixed => [
            '/pd-sec-remaining/a.txt' => ['id' => 1, 'timestamp' => time(), 'data' => serialize($this->canary())],
        ]));
        $this->resetCanary();

        $log = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();

        $this->assertArrayNotHasKey('/pd-sec-remaining/a.txt', $log);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the WebDAV delete log.');
    }

    public function testDeleteLogWithInvalidPayloadIsEmpty(): void
    {
        $this->writeDeleteLog('not a serialized payload');

        $this->assertSame([], \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
    }

    public function testMoveOverDeleteLoggedPathNeverInstantiatesForeignClassFromLog(): void
    {
        $this->prepareFolder();
        $source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $this->authenticate($this->createAdmin());
        $this->writeDeleteLog($this->serialized(fn (): mixed => [
            '/' . self::FOLDER . '/ghost.txt' => ['id' => 1, 'timestamp' => time(), 'data' => serialize($this->canary())],
        ]));
        $this->resetCanary();

        $status = $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran during a WebDAV MOVE.');
        $this->assertContains($status, [201, 204]);
        $moved = \Pimcore\Model\Asset::getById($source->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $moved);
        $this->assertSame('/' . self::FOLDER . '/ghost.txt', $moved->getRealFullPath());
    }

    public function testMoveOverDeleteLoggedPathStillRestoresDeletedAsset(): void
    {
        $this->prepareFolder();
        $source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $ghost = $this->createTextAsset('ghost.txt', self::GHOST_DATA);
        $this->authenticate($this->createAdmin());
        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
        $this->assertNull(\Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]));

        $status = $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt');

        $this->assertContains($status, [201, 204]);
        $restored = \Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $restored);
        $this->assertSame('/' . self::FOLDER . '/ghost.txt', $restored->getRealFullPath());
        $this->assertSame(self::SOURCE_DATA, $restored->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($source->getId(), ['force' => true]));
    }

    public function testControlDeleteThenMoveRestoresDeletedAssetOfOverriddenClass(): void
    {
        $this->prepareFolder();
        $this->overrideAssetClass(\Pimcore\Model\Asset\Text::class, \Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class);
        $source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $ghost = $this->createTextAsset('ghost.txt', self::GHOST_DATA);
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class, $ghost);
        $this->authenticate($this->createAdmin());

        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->assertNull(\Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]));
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());

        $this->assertSame(201, $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt'));

        $restored = \Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]);
        $this->assertInstanceOf(\Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class, $restored);
        $this->assertSame('/' . self::FOLDER . '/ghost.txt', $restored->getRealFullPath());
        $this->assertSame(self::SOURCE_DATA, $restored->getData());
        $this->assertNull(\Pimcore\Model\Asset::getById($source->getId(), ['force' => true]));
    }

    public function testDeleteLogKeepsEntryOfOverriddenAssetClassAndDropsEntryWithForeignClass(): void
    {
        $this->prepareFolder();
        $this->overrideAssetClass(\Pimcore\Model\Asset\Text::class, \Portadesign\PimcoreSecurityPatches\Tests\Support\OverriddenTextAsset::class);
        $ghost = $this->createTextAsset('ghost.txt', self::GHOST_DATA);
        $this->authenticate($this->createAdmin());
        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $this->resetCanary();

        $log = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();
        $log['/' . self::FOLDER . '/foreign.txt'] = ['id' => 1, 'timestamp' => time(), 'data' => serialize($this->canary())];
        \Pimcore\Model\Asset\WebDAV\Service::saveDeleteLog($log);
        $this->resetCanary();

        $kept = array_filter(
            \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog(),
            static fn (string|int $path): bool => str_starts_with((string) $path, '/' . self::FOLDER . '/'),
            ARRAY_FILTER_USE_KEY,
        );

        $this->assertSame(['/' . self::FOLDER . '/ghost.txt'], array_keys($kept));
        $this->assertSame($ghost->getId(), $kept['/' . self::FOLDER . '/ghost.txt']['id']);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the WebDAV delete log.');
    }

    public function testControlDeleteThenMoveRestoresAssetWithPropertiesAndDependencies(): void
    {
        $this->prepareFolder();
        $source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $ghost = $this->createTextAsset('ghost.txt', self::GHOST_DATA);
        $ghost->setProperty('pd-sec-reference', 'asset', $this->folder, false, false);
        $ghost->setProperty('pd-sec-date', 'date', \Carbon\Carbon::parse('2024-01-02 03:04:05'), false, false);
        $ghost->save();
        $this->authenticate($this->createAdmin());

        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/ghost.txt'));
        $logged = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();
        $this->assertArrayHasKey('/' . self::FOLDER . '/ghost.txt', $logged);

        $this->assertSame(201, $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/ghost.txt'));

        $restored = \Pimcore\Model\Asset::getById($ghost->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $restored);
        $this->assertSame(self::SOURCE_DATA, $restored->getData());
        $this->assertSame($this->folder->getId(), $restored->getProperty('pd-sec-reference')->getId());
        $this->assertNull(\Pimcore\Model\Asset::getById($source->getId(), ['force' => true]));
    }

    public function testRenameAndDeleteStillWorkWithLegitimateLog(): void
    {
        $this->prepareFolder();
        $source = $this->createTextAsset('source.txt', self::SOURCE_DATA);
        $this->authenticate($this->createAdmin());

        $this->assertSame(201, $this->request('MOVE', '/' . self::FOLDER . '/source.txt', '/' . self::FOLDER . '/renamed.txt'));
        $renamed = \Pimcore\Model\Asset::getById($source->getId(), ['force' => true]);
        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $renamed);
        $this->assertSame('/' . self::FOLDER . '/renamed.txt', $renamed->getRealFullPath());

        $this->assertSame(204, $this->request('DELETE', '/' . self::FOLDER . '/renamed.txt'));
        $this->assertNull(\Pimcore\Model\Asset::getById($source->getId(), ['force' => true]));
        $this->assertArrayHasKey('/' . self::FOLDER . '/renamed.txt', \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
    }

    public function testTableColumnDataRejectsTopLevelForeignClass(): void
    {
        $result = $this->tableField()->getDataFromResource($this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame([], $result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Table data.');
    }

    public function testTableColumnDataDoesNotInstantiateNestedForeignClass(): void
    {
        $result = $this->tableField()->getDataFromResource($this->serialized(fn (): mixed => [['a', $this->canary()]]));

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result[0][1]);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Table data.');
    }

    public function testTableColumnDataLoadsLegitimateRows(): void
    {
        $rows = [['a', 'b'], ['c', 'd']];

        $this->assertSame($rows, $this->tableField()->getDataFromResource(serialize($rows)));
    }

    public function testBlockReloadKeepsDateRangeAndHotspotimage(): void
    {
        $this->prepareFolder();
        $image = $this->createImageAsset();
        $range = new \Pimcore\Model\DataObject\ClassDefinition\Data\DateRange();
        $range->setName('range');
        $hotspot = new \Pimcore\Model\DataObject\ClassDefinition\Data\Hotspotimage();
        $hotspot->setName('hs');
        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('blk');
        $block->setChildren([$range, $hotspot]);
        $params = ['owner' => new \Pimcore\Model\DataObject\Concrete(), 'fieldname' => 'blk'];
        $period = \Carbon\CarbonPeriod::create(\Carbon\Carbon::parse('2024-01-01'), \Carbon\Carbon::parse('2024-01-03'));
        $hotspotImage = new \Pimcore\Model\DataObject\Data\Hotspotimage($image, [['name' => 'h', 'data' => [$this->markerItem()]]], [['name' => 'm', 'data' => [$this->markerItem()]]], []);

        $stored = $block->getDataForResource([[
            'range' => new \Pimcore\Model\DataObject\Data\BlockElement('range', 'daterange', $period),
            'hs' => new \Pimcore\Model\DataObject\Data\BlockElement('hs', 'hotspotimage', $hotspotImage),
        ]], null, $params);
        $loaded = $block->getDataFromResource($stored, null, $params);

        $this->assertIsArray($loaded);
        $loadedRange = $loaded[0]['range']->getData();
        $this->assertInstanceOf(\Carbon\CarbonPeriod::class, $loadedRange);
        $this->assertSame('2024-01-01', $loadedRange->getStartDate()->format('Y-m-d'));
        $this->assertSame('2024-01-03', $loadedRange->getEndDate()->format('Y-m-d'));
        $loadedHotspot = $loaded[0]['hs']->getData();
        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Hotspotimage::class, $loadedHotspot);
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loadedHotspot->getHotspots()[0]['data'][0]);
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loadedHotspot->getMarker()[0]['data'][0]);
    }

    public function testBlockDoesNotInstantiateForeignClass(): void
    {
        $block = new \Pimcore\Model\DataObject\ClassDefinition\Data\Block();
        $block->setName('blk');

        try {
            $block->getDataFromResource($this->serialized(fn (): mixed => [['range' => ['name' => 'range', 'type' => 'daterange', 'data' => [$this->canary()]]]]), null, ['owner' => new \Pimcore\Model\DataObject\Concrete(), 'fieldname' => 'blk']);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Block data.');
    }

    public function testImageEditableReloadKeepsHotspotAndMarkerItems(): void
    {
        $this->prepareFolder();
        $image = $this->createImageAsset();
        $editable = new \Pimcore\Model\Document\Editable\Image();
        $editable->setName('img');

        $editable->setDataFromResource(serialize([
            'id' => $image->getId(),
            'alt' => 'pd-sec',
            'hotspots' => [['name' => 'h', 'data' => [$this->markerItem()]]],
            'marker' => [['name' => 'm', 'data' => [$this->markerItem()]]],
        ]));
        $editmode = $editable->getDataEditmode();

        $this->assertIsArray($editmode);
        $this->assertSame('label', $editmode['hotspots'][0]['data'][0]['name']);
        $this->assertSame('label', $editmode['marker'][0]['data'][0]['name']);
    }

    public function testImageEditableDoesNotInstantiateForeignClass(): void
    {
        $editable = new \Pimcore\Model\Document\Editable\Image();
        $editable->setName('img');

        try {
            $editable->setDataFromResource($this->serialized(fn (): mixed => ['id' => 1, 'hotspots' => [['name' => 'h', 'data' => [$this->canary()]]]]));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading an Image editable.');
    }

    public function testImageGalleryReloadKeepsHotspotItems(): void
    {
        $this->prepareFolder();
        $image = $this->createImageAsset();
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\ImageGallery();
        $field->setName('gal');
        $gallery = new \Pimcore\Model\DataObject\Data\ImageGallery([
            new \Pimcore\Model\DataObject\Data\Hotspotimage($image, [['name' => 'h', 'data' => [$this->markerItem()]]], [], []),
        ]);

        $loaded = $field->getDataFromResource($field->getDataForResource($gallery));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\ImageGallery::class, $loaded);
        $this->assertCount(1, $loaded->getItems());
        $this->assertSame($image->getId(), $loaded->getItems()[0]->getImage()->getId());
        $this->assertInstanceOf(\Pimcore\Model\Element\Data\MarkerHotspotItem::class, $loaded->getItems()[0]->getHotspots()[0]['data'][0]);
    }

    public function testVideoReloadKeepsValues(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Video();
        $video = new \Pimcore\Model\DataObject\Data\Video();
        $video->setType('youtube');
        $video->setData('pd-sec-video');
        $video->setTitle('pd-sec-title');

        $loaded = $field->getDataFromResource($field->getDataForResource($video));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Video::class, $loaded);
        $this->assertSame('youtube', $loaded->getType());
        $this->assertSame('pd-sec-video', $loaded->getData());
        $this->assertSame('pd-sec-title', $loaded->getTitle());
    }

    public function testGeopolygonReloadKeepsCoordinates(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon();
        $points = [new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5), new \Pimcore\Model\DataObject\Data\GeoCoordinates(3.5, 4.5)];

        $loaded = $field->getDataFromResource($field->getDataForResource($points));

        $this->assertCount(2, $loaded);
        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\GeoCoordinates::class, $loaded[1]);
        $this->assertSame(3.5, $loaded[1]->getLatitude());
        $this->assertSame(4.5, $loaded[1]->getLongitude());
    }

    public function testAssetCustomSettingsKeepStdClassPayload(): void
    {
        $asset = new \Pimcore\Model\Asset\Text();

        $asset->setCustomSettings(serialize((object) ['pd-sec' => 'value']));

        $this->assertSame(['pd-sec' => 'value'], $asset->getCustomSettings());
    }

    public function testAssetCustomSettingsDoNotInstantiateForeignClass(): void
    {
        $asset = new \Pimcore\Model\Asset\Text();

        $asset->setCustomSettings($this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame([], $asset->getCustomSettings());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading asset custom settings.');
    }

    public function testClassificationstoreTableMarshallerReloadsRows(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\Table();
        $rows = [['a', 'b'], ['c', 'd']];

        $this->assertSame($rows, $marshaller->unmarshal($marshaller->marshal($rows)));
    }

    public function testClassificationstoreTableMarshallerDoesNotInstantiateForeignClass(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\Table();

        $marshaller->unmarshal(['value' => $this->serialized(fn (): mixed => $this->canary())]);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in the Classificationstore Table marshaller.');
    }

    public function testClassificationstoreQuantityValueRangeMarshallerReloadsRange(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\QuantityValueRange();
        $range = ['minimum' => 1, 'maximum' => 5, 'unitId' => 'pd-sec-unit'];

        $this->assertSame($range, $marshaller->unmarshal($marshaller->marshal($range)));
    }

    public function testClassificationstoreQuantityValueRangeMarshallerDoesNotInstantiateForeignClass(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\QuantityValueRange();

        try {
            $marshaller->unmarshal(['value' => $this->serialized(fn (): mixed => $this->canary()), 'value2' => null]);
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in the Classificationstore QuantityValueRange marshaller.');
    }

    public function testSessionElementRoundTripsWhenSigned(): void
    {
        $asset = $this->sessionAsset();

        \Pimcore\Model\Element\Service::saveElementToSession($asset, self::SESSION_ID);
        $loaded = \Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), self::SESSION_ID);

        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $loaded);
        $this->assertSame($asset->getId(), $loaded->getId());
    }

    public function testSessionElementWithForeignClassInUnsignedRowIsRejected(): void
    {
        $asset = $this->sessionAsset();
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), $this->serialized(fn (): mixed => $this->canary()), 'asset-session');

        $loaded = \Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), self::SESSION_ID);

        $this->assertNull($loaded);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading a session element.');
    }

    public function testSessionElementWithoutSignatureIsRejected(): void
    {
        $asset = $this->sessionAsset();
        \Pimcore\Model\Element\Service::saveElementToSession($asset, self::SESSION_ID);
        $stored = (string) \Pimcore\Model\Tool\TmpStore::get($this->sessionKey($asset))?->getData();
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), substr($stored, 64), 'asset-session');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), self::SESSION_ID));
    }

    public function testSessionElementWithTamperedPayloadIsRejected(): void
    {
        $asset = $this->sessionAsset();
        \Pimcore\Model\Element\Service::saveElementToSession($asset, self::SESSION_ID);
        $stored = (string) \Pimcore\Model\Tool\TmpStore::get($this->sessionKey($asset))?->getData();
        $stored[100] = 'a' === $stored[100] ? 'b' : 'a';
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), $stored, 'asset-session');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), self::SESSION_ID));
    }

    public function testSessionElementSignedForAnotherKeyIsRejected(): void
    {
        $asset = $this->sessionAsset();
        \Pimcore\Model\Element\Service::saveElementToSession($asset, self::SESSION_ID);
        $stored = (string) \Pimcore\Model\Tool\TmpStore::get($this->sessionKey($asset))?->getData();
        \Pimcore\Model\Tool\TmpStore::set(\Pimcore\Model\Element\Service::getSessionKey('asset', $asset->getId(), self::SESSION_ID, '_other'), $stored, 'asset-session_other');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), self::SESSION_ID, '_other'));
    }

    /**
     * @return array<string, array{class-string<\Pimcore\Model\DataObject\ClassDefinition\Data>}>
     */
    public static function geoPointListFieldProvider(): array
    {
        return [
            'geopolygon' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon::class],
            'geopolyline' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolyline::class],
        ];
    }

    /**
     * @param class-string<\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon|\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolyline> $fieldClass
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('geoPointListFieldProvider')]
    public function testGeoPointListKeepsCoordinatesAndNeverInstantiatesForeignClass(string $fieldClass): void
    {
        $field = new $fieldClass();
        $payload = $this->serialized(fn (): mixed => [new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5), $this->canary()]);

        $loaded = $field->getDataFromResource($payload);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\GeoCoordinates::class, $loaded[0]);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $loaded[1]);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading ' . $fieldClass . ' data.');
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

    public function testVideoNeverInstantiatesForeignClassInStoredValue(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Video();

        try {
            $field->getDataFromResource($this->serialized(fn (): mixed => $this->canary()));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Video data.');
    }

    public function testDeleteLogIgnoresMalformedEntriesAndStaysUsable(): void
    {
        $valid = ['id' => 1, 'timestamp' => time(), 'data' => serialize(['plain' => 1])];
        $this->writeDeleteLog(serialize([
            '/pd-sec-remaining/not-an-array' => 'text',
            '/pd-sec-remaining/no-timestamp' => ['id' => 1, 'data' => serialize(['plain' => 1])],
            '/pd-sec-remaining/no-data' => ['id' => 1, 'timestamp' => time()],
            '/pd-sec-remaining/data-not-string' => ['id' => 1, 'timestamp' => time(), 'data' => ['plain' => 1]],
            '/pd-sec-remaining/valid' => $valid,
        ]));

        $log = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();

        $this->assertSame(['/pd-sec-remaining/valid'], array_keys($log));
        \Pimcore\Model\Asset\WebDAV\Service::saveDeleteLog($log);
        $this->assertSame($log, \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
    }

    public function testDatePropertyDoesNotInstantiateForeignClass(): void
    {
        $property = new \Pimcore\Model\Property();
        $property->setType('date');

        $property->setDataFromResource($this->serialized(fn (): mixed => $this->canary()));

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $property->getData());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading a date property.');
    }

    public function testDatePropertyLoadsCarbonDate(): void
    {
        $property = new \Pimcore\Model\Property();
        $property->setType('date');

        $property->setDataFromResource(serialize(\Carbon\Carbon::createFromTimestamp(1700000000)));

        $this->assertInstanceOf(\Carbon\Carbon::class, $property->getData());
        $this->assertSame(1700000000, $property->getData()->getTimestamp());
    }

    public function testLinkFieldDoesNotInstantiateForeignClass(): void
    {
        $result = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Link())->getDataFromResource($this->serialized(fn (): mixed => $this->canary()));

        $this->assertNull($result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading a Link field.');
    }

    public function testLinkFieldLoadsLegitimateLink(): void
    {
        $link = new \Pimcore\Model\DataObject\Data\Link();
        $link->setLinktype('direct');
        $link->setDirect('https://example.com/pd-sec');
        $link->setText('pd-sec');

        $result = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Link())->getDataFromResource(serialize($link));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Link::class, $result);
        $this->assertSame('https://example.com/pd-sec', $result->getDirect());
    }

    public function testDashboardConfigFileWithForeignClassIsRejected(): void
    {
        $dashboard = $this->dashboardWithFile($this->serialized(fn (): mixed => $this->canary()));

        $dashboards = $dashboard->getAllDashboards();

        $this->assertIsArray($dashboards);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the dashboard config.');
    }

    public function testDashboardConfigFileWithNestedForeignClassIsNotInstantiated(): void
    {
        $dashboard = $this->dashboardWithFile($this->serialized(fn (): mixed => ['custom' => ['positions' => [[], []], 'gadget' => $this->canary()]]));

        $dashboard->getAllDashboards();

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the dashboard config.');
    }

    public function testDashboardConfigFileLoadsLegitimateConfiguration(): void
    {
        $dashboard = $this->dashboardWithFile(serialize(['pd-sec-custom' => ['positions' => [[['id' => 1, 'type' => 'pimcore.layout.portlets.modificationStatistic', 'config' => null]], []]]]));

        $dashboards = $dashboard->getAllDashboards();

        $this->assertIsArray($dashboards);
        $this->assertSame('pimcore.layout.portlets.modificationStatistic', $dashboards['pd-sec-custom']['positions'][0][0]['type']);
    }

    public function testErrorLogDetailDoesNotInstantiateForeignClassInParameters(): void
    {
        $response = $this->errorLogDetail($this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString(self::ERROR_LOG_URI, (string) $response->getContent());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while rendering the HTTP error log detail.');
    }

    public function testErrorLogDetailDoesNotInstantiateNestedForeignClassInParameters(): void
    {
        $this->errorLogDetail($this->serialized(fn (): mixed => ['q' => 'v', 'gadget' => $this->canary()]));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while rendering the HTTP error log detail.');
    }

    public function testErrorLogDetailShowsLegitimateParameters(): void
    {
        $response = $this->errorLogDetail(serialize(['pd-sec-key' => 'pd-sec-value']));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('pd-sec-key', (string) $response->getContent());
        $this->assertStringContainsString('pd-sec-value', (string) $response->getContent());
    }

    private function errorLogDetail(string $parametersGet): \Symfony\Component\HttpFoundation\Response
    {
        $controllerClass = 'Pimcore\\Bundle\\SeoBundle\\Controller\\MiscController';
        $db = \Pimcore\Db::get();
        if (!class_exists($controllerClass) || !$db->createSchemaManager()->tablesExist(['http_error_log'])) {
            self::markTestSkipped('The SEO bundle with its http_error_log table is not installed.');
        }

        $this->deleteErrorLogRow();
        $db->insert('http_error_log', ['uri' => self::ERROR_LOG_URI, 'code' => 404, 'parametersGet' => $parametersGet, 'date' => time(), 'count' => 1]);
        $this->authenticate($this->createAdmin());
        $this->resetCanary();

        return \Pimcore::getContainer()->get($controllerClass)->httpErrorLogDetailAction(
            new \Symfony\Component\HttpFoundation\Request(['uri' => self::ERROR_LOG_URI]),
            null,
        );
    }

    private function deleteErrorLogRow(): void
    {
        $db = \Pimcore\Db::get();
        if ($db->createSchemaManager()->tablesExist(['http_error_log'])) {
            $db->delete('http_error_log', ['uri' => self::ERROR_LOG_URI]);
        }
    }

    private function markerItem(): \Pimcore\Model\Element\Data\MarkerHotspotItem
    {
        return new \Pimcore\Model\Element\Data\MarkerHotspotItem(['name' => 'label', 'type' => 'input', 'value' => 'v']);
    }

    private function createImageAsset(): \Pimcore\Model\Asset\Image
    {
        $image = \Pimcore\Model\Asset::create($this->folder->getId(), [
            'filename' => 'pixel.png',
            'data' => (string) base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='),
        ]);
        self::assertInstanceOf(\Pimcore\Model\Asset\Image::class, $image);

        return $image;
    }

    private function sessionAsset(): \Pimcore\Model\Asset
    {
        $this->prepareFolder();
        $asset = $this->createTextAsset('session.txt', 'pd-sec-session');
        $this->sessionAssets[] = $asset->getId();

        return $asset;
    }

    private function sessionKey(\Pimcore\Model\Asset $asset): string
    {
        return \Pimcore\Model\Element\Service::getSessionKey('asset', $asset->getId(), self::SESSION_ID);
    }

    private function removeSessionRows(): void
    {
        foreach ($this->sessionAssets as $assetId) {
            foreach (['', '_other'] as $postfix) {
                \Pimcore\Model\Element\Service::removeElementFromSession('asset', $assetId, self::SESSION_ID, $postfix);
            }
        }

        $this->sessionAssets = [];
    }

    private function tableField(): \Pimcore\Model\DataObject\ClassDefinition\Data\Table
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Table();
        $field->setName('tbl');

        return $field;
    }

    private function dashboardWithFile(string $contents): \Pimcore\Bundle\AdminBundle\Helper\Dashboard
    {
        $this->dashboardUser = \Pimcore\Model\User::getByName(self::DASHBOARD_USERNAME);
        if (!$this->dashboardUser instanceof \Pimcore\Model\User) {
            $this->dashboardUser = \Pimcore\Model\User::create([
                'parentId' => 0,
                'name' => self::DASHBOARD_USERNAME,
                'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
                'active' => false,
            ]);
        }
        $this->authenticate($this->dashboardUser);
        $dashboard = new \Pimcore\Bundle\AdminBundle\Helper\Dashboard($this->dashboardUser);
        $file = $this->dashboardFile();
        if (!is_dir(dirname($file))) {
            mkdir(dirname($file), 0775, true);
        }
        $this->originalDashboard = is_file($file) ? (string) file_get_contents($file) : null;
        file_put_contents($file, $contents);
        $this->resetCanary();

        return $dashboard;
    }

    private function dashboardFile(): string
    {
        return PIMCORE_CONFIGURATION_DIRECTORY . '/portal/dashboards_' . $this->dashboardUser?->getId() . '.psf';
    }

    private function restoreDashboard(): void
    {
        if (!$this->dashboardUser instanceof \Pimcore\Model\User) {
            return;
        }

        $file = $this->dashboardFile();
        if (null === $this->originalDashboard) {
            @unlink($file);
        } else {
            file_put_contents($file, $this->originalDashboard);
        }

        $this->dashboardUser->delete();
        $this->dashboardUser = null;
    }

    private function writeDeleteLog(string $contents): void
    {
        file_put_contents(\Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile(), $contents);
    }

    private function restoreDeleteLog(): void
    {
        $logFile = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile();
        if (null === $this->originalDeleteLog) {
            @unlink($logFile);
        } else {
            file_put_contents($logFile, $this->originalDeleteLog);
        }
    }

    private function overrideAssetClass(string $source, string $target): void
    {
        $factory = \Pimcore::getContainer()->get('pimcore.model.factory');
        $loaders = new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaders');
        $cache = new \ReflectionProperty(\Pimcore\Loader\ImplementationLoader\ImplementationLoader::class, 'loaderCache');
        $this->originalFactoryState = [$loaders->getValue($factory), $cache->getValue($factory)];

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

    private function prepareFolder(): void
    {
        $this->deleteAssetByPath('/' . self::FOLDER);
        $this->folder = $this->createAssetFolder(parentId: 1, filename: self::FOLDER);
    }

    private function createAdmin(): \Pimcore\Model\User
    {
        $this->deleteUserByName(self::ADMIN_USERNAME);

        return \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::ADMIN_USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => false,
            'admin' => true,
        ]);
    }

    private function createTextAsset(string $filename, string $data): \Pimcore\Model\Asset
    {
        return \Pimcore\Model\Asset::create($this->folder->getId(), [
            'filename' => $filename,
            'data' => $data,
        ]);
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
        }

        return $response->getStatus();
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
