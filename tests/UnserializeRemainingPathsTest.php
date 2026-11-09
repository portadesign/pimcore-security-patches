<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45162')]
final class UnserializeRemainingPathsTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AssetFolderFixture;

    private const ADMIN_USERNAME = 'pd-sec-unserialize-remaining-admin';

    private const FOLDER = 'pd-sec-unserialize-remaining';

    private const ERROR_LOG_URI = '/pd-sec-unserialize-remaining-error-log';

    private ?string $originalDeleteLog = null;

    /**
     * @var list<\Closure>
     */
    private array $cleanups = [];

    protected function setUp(): void
    {
        $this->resetCanary();
        \Pimcore\Model\Version::disable();
        $logFile = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLogFile();
        $this->originalDeleteLog = is_file($logFile) ? (string) file_get_contents($logFile) : null;
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        foreach (array_reverse($this->cleanups) as $cleanup) {
            $cleanup();
        }
        $this->cleanups = [];
        $this->restoreDeleteLog();
        $this->deleteUserByName(self::ADMIN_USERNAME);
        $this->deleteAssetByPath('/' . self::FOLDER);
        \Pimcore\Model\Version::enable();
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

    public function testControlDeleteLogWithInvalidPayloadIsEmpty(): void
    {
        $this->writeDeleteLog('not a serialized payload');

        $this->assertSame([], @\Pimcore\Model\Asset\WebDAV\Service::getDeleteLog());
    }

    public function testControlDeleteLogRoundTripsLegitimateEntry(): void
    {
        $this->prepareFolder();
        $asset = \Pimcore\Model\Asset::create($this->folderId(), ['filename' => 'logged.txt', 'data' => 'pd-sec-logged']);
        $entry = ['id' => $asset->getId(), 'timestamp' => time(), 'data' => serialize($asset)];

        \Pimcore\Model\Asset\WebDAV\Service::saveDeleteLog(['/' . self::FOLDER . '/logged.txt' => $entry]);
        $log = \Pimcore\Model\Asset\WebDAV\Service::getDeleteLog();

        $this->assertSame(['/' . self::FOLDER . '/logged.txt'], array_keys($log));
        $this->assertSame($asset->getId(), $log['/' . self::FOLDER . '/logged.txt']['id']);
        $this->assertSame(serialize($asset), $log['/' . self::FOLDER . '/logged.txt']['data']);
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

    public function testControlTableColumnDataLoadsLegitimateRows(): void
    {
        $rows = [['a', 'b'], ['c', 'd']];

        $this->assertSame($rows, $this->tableField()->getDataFromResource(serialize($rows)));
    }

    public function testLinkFieldDoesNotInstantiateForeignClass(): void
    {
        $result = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Link())->getDataFromResource($this->serialized(fn (): mixed => $this->canary()));

        $this->assertNull($result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading a Link field.');
    }

    public function testControlLinkFieldLoadsLegitimateLink(): void
    {
        $link = new \Pimcore\Model\DataObject\Data\Link();
        $link->setLinktype('direct');
        $link->setDirect('https://example.com/pd-sec');
        $link->setText('pd-sec');

        $result = (new \Pimcore\Model\DataObject\ClassDefinition\Data\Link())->getDataFromResource(serialize($link));

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\Link::class, $result);
        $this->assertSame(['https://example.com/pd-sec', 'pd-sec'], [$result->getDirect(), $result->getText()]);
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
    public function testGeoPointListNeverInstantiatesForeignClassAndKeepsCoordinates(string $fieldClass): void
    {
        $field = new $fieldClass();
        $payload = $this->serialized(fn (): mixed => [new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5), $this->canary()]);

        $loaded = $field->getDataFromResource($payload);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\Data\GeoCoordinates::class, $loaded[0]);
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $loaded[1]);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading ' . $fieldClass . ' data.');
    }

    public function testControlGeopolygonReloadKeepsCoordinates(): void
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon();
        $points = [new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5), new \Pimcore\Model\DataObject\Data\GeoCoordinates(3.5, 4.5)];

        $loaded = $field->getDataFromResource($field->getDataForResource($points));

        $this->assertCount(2, $loaded);
        $this->assertSame([3.5, 4.5], [$loaded[1]->getLatitude(), $loaded[1]->getLongitude()]);
    }

    /**
     * @return array<string, array{class-string<\Pimcore\Model\DataObject\ClassDefinition\Data>}>
     */
    public static function decryptedValueFieldProvider(): array
    {
        return [
            'geopoint' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geopoint::class],
            'geobounds' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geobounds::class],
            'geopolygon' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon::class],
            'geopolyline' => [\Pimcore\Model\DataObject\ClassDefinition\Data\Geopolyline::class],
            'rgba color' => [\Pimcore\Model\DataObject\ClassDefinition\Data\RgbaColor::class],
        ];
    }

    /**
     * @param class-string<\Pimcore\Model\DataObject\ClassDefinition\Data> $fieldClass
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('decryptedValueFieldProvider')]
    public function testEncryptedValueNeverInstantiatesForeignClass(string $fieldClass): void
    {
        $field = new $fieldClass();

        $field->unmarshalAfterDecryption($this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in ' . $fieldClass . '::unmarshalAfterDecryption().');
    }

    /**
     * @return array<string, array{class-string<\Pimcore\Model\DataObject\ClassDefinition\Data>, \Closure(): mixed}>
     */
    public static function legitimateDecryptedValueProvider(): array
    {
        return [
            'geopoint' => [
                \Pimcore\Model\DataObject\ClassDefinition\Data\Geopoint::class,
                static fn (): mixed => new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5),
            ],
            'geobounds' => [
                \Pimcore\Model\DataObject\ClassDefinition\Data\Geobounds::class,
                static fn (): mixed => new \Pimcore\Model\DataObject\Data\Geobounds(
                    new \Pimcore\Model\DataObject\Data\GeoCoordinates(4.5, 5.5),
                    new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5),
                ),
            ],
            'geopolygon' => [
                \Pimcore\Model\DataObject\ClassDefinition\Data\Geopolygon::class,
                static fn (): mixed => [
                    new \Pimcore\Model\DataObject\Data\GeoCoordinates(1.5, 2.5),
                    new \Pimcore\Model\DataObject\Data\GeoCoordinates(3.5, 4.5),
                ],
            ],
            'rgba color' => [
                \Pimcore\Model\DataObject\ClassDefinition\Data\RgbaColor::class,
                static fn (): mixed => new \Pimcore\Model\DataObject\Data\RgbaColor(10, 20, 30, 40),
            ],
        ];
    }

    /**
     * @param class-string<\Pimcore\Model\DataObject\ClassDefinition\Data> $fieldClass
     * @param \Closure(): mixed $factory
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('legitimateDecryptedValueProvider')]
    public function testControlEncryptedValueRoundTripsLegitimateValue(string $fieldClass, \Closure $factory): void
    {
        $field = new $fieldClass();
        $value = $factory();

        $restored = $field->unmarshalAfterDecryption($field->marshalBeforeEncryption($value));

        $this->assertEquals($value, $restored);
    }

    public function testDatePropertyDoesNotInstantiateForeignClass(): void
    {
        $property = new \Pimcore\Model\Property();
        $property->setType('date');

        $property->setDataFromResource($this->serialized(fn (): mixed => $this->canary()));

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $property->getData());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading a date property.');
    }

    public function testControlDatePropertyLoadsCarbonDate(): void
    {
        $property = new \Pimcore\Model\Property();
        $property->setType('date');

        $property->setDataFromResource(serialize(\Carbon\Carbon::createFromTimestamp(1700000000)));

        $this->assertInstanceOf(\Carbon\Carbon::class, $property->getData());
        $this->assertSame(1700000000, $property->getData()->getTimestamp());
    }

    public function testAssetCustomSettingsDoNotInstantiateForeignClass(): void
    {
        $asset = new \Pimcore\Model\Asset\Text();

        $asset->setCustomSettings($this->serialized(fn (): mixed => $this->canary()));

        $this->assertSame([], $asset->getCustomSettings());
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading asset custom settings.');
    }

    public function testAssetCustomSettingsDoNotInstantiateNestedForeignClass(): void
    {
        $asset = new \Pimcore\Model\Asset\Text();

        $asset->setCustomSettings($this->serialized(fn (): mixed => (object) ['pd-sec' => $this->canary()]));

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $asset->getCustomSettings()['pd-sec']);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading asset custom settings.');
    }

    public function testControlAssetCustomSettingsKeepStdClassPayload(): void
    {
        $asset = new \Pimcore\Model\Asset\Text();

        $asset->setCustomSettings(serialize((object) ['pd-sec' => 'value']));

        $this->assertSame(['pd-sec' => 'value'], $asset->getCustomSettings());
    }

    public function testClassificationstoreTableMarshallerDoesNotInstantiateForeignClass(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\Table();

        $marshaller->unmarshal(['value' => $this->serialized(fn (): mixed => $this->canary())]);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in the Classificationstore Table marshaller.');
    }

    public function testControlClassificationstoreTableMarshallerReloadsRows(): void
    {
        $marshaller = new \Pimcore\DataObject\ClassificationstoreDataMarshaller\Table();
        $rows = [['a', 'b'], ['c', 'd']];

        $this->assertSame($rows, $marshaller->unmarshal($marshaller->marshal($rows)));
    }

    public function testPageMetaDataFromDatabaseDoesNotInstantiateForeignClass(): void
    {
        $id = $this->createPage();
        \Pimcore\Db::get()->update('documents_page', ['metaData' => $this->serialized(fn (): mixed => [['name' => 'robots', 'value' => $this->canary()]])], ['id' => $id]);
        $this->resetCanary();

        \Pimcore\Model\Document\Page::getById($id, ['force' => true]);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while loading Page metaData.');
    }

    public function testControlPageMetaDataFromDatabaseKeepsLegitimateEntries(): void
    {
        $id = $this->createPage();
        $entries = [['name' => 'robots', 'value' => 'noindex']];
        \Pimcore\Db::get()->update('documents_page', ['metaData' => serialize($entries)], ['id' => $id]);

        $page = \Pimcore\Model\Document\Page::getById($id, ['force' => true]);

        $this->assertSame($entries, $page->getMetaData());
    }

    public function testTargetingRuleDoesNotInstantiateForeignClassInConditionsOrActions(): void
    {
        $id = $this->insertTargetingRule(
            $this->serialized(fn (): mixed => [['type' => 'country', 'gadget' => $this->canary()]]),
            $this->serialized(fn (): mixed => [['type' => 'redirect', 'gadget' => $this->canary()]]),
        );
        $this->resetCanary();

        \Pimcore\Model\Tool\Targeting\Rule::getById($id);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in Targeting\\Rule\\Dao::getById().');
    }

    public function testControlTargetingRuleKeepsLegitimateConditionsAndActions(): void
    {
        $conditions = [['type' => 'country', 'countries' => ['CZ']]];
        $actions = [['type' => 'redirect', 'url' => '/pd-sec']];
        $id = $this->insertTargetingRule(serialize($conditions), serialize($actions));

        $rule = \Pimcore\Model\Tool\Targeting\Rule::getById($id);

        $this->assertSame([$conditions, $actions], [$rule->getConditions(), $rule->getActions()]);
    }

    public function testPhpGridOperatorInUnserializeModeDoesNotInstantiateForeignClass(): void
    {
        $result = $this->phpOperator('u', $this->serialized(fn (): mixed => $this->canary()))->getLabeledValue(new \Pimcore\Model\DataObject\Folder());

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $result->value);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in the PHP grid operator.');
    }

    public function testControlPhpGridOperatorInUnserializeModeRestoresArray(): void
    {
        $result = $this->phpOperator('u', serialize(['a' => 1, 'b' => ['c']]))->getLabeledValue(new \Pimcore\Model\DataObject\Folder());

        $this->assertSame(['a' => 1, 'b' => ['c']], $result->value);
    }

    /**
     * @return array<string, array{class-string<\Pimcore\Model\Document\Editable>}>
     */
    public static function editableProvider(): array
    {
        $cases = [];
        foreach (['Area', 'Relation', 'Relations', 'Renderlet', 'Link', 'Block', 'Areablock', 'Embed', 'Video', 'Pdf', 'Image', 'Multiselect', 'Table'] as $name) {
            $cases[$name] = ['Pimcore\\Model\\Document\\Editable\\' . $name];
        }

        return $cases;
    }

    /**
     * @return array<string, array{\Closure(\Closure): mixed}>
     */
    public static function editablePayloadProvider(): array
    {
        return [
            'top level object' => [static fn (\Closure $canary): mixed => $canary()],
            'canary nested in list' => [static fn (\Closure $canary): mixed => ['a', $canary()]],
            'canary nested in map' => [static fn (\Closure $canary): mixed => [
                'id' => 1,
                'type' => 'asset',
                'subtype' => 'folder',
                'url' => 'https://example.com',
                'poster' => null,
                'title' => null,
                'description' => null,
                'alt' => 'alt',
                'hotspots' => [['name' => 'h', 'data' => [$canary()]]],
                'extra' => $canary(),
            ]],
        ];
    }

    /**
     * @param class-string<\Pimcore\Model\Document\Editable> $class
     * @param \Closure(\Closure): mixed $payload
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('editableProvider')]
    public function testEditableNeverInstantiatesForeignClass(string $class): void
    {
        foreach (self::editablePayloadProvider() as $label => [$payload]) {
            $editable = new $class();
            $editable->setName('pd-sec');
            $serialized = \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized(
                fn (): mixed => $payload(fn (): object => $this->canary()),
            );

            try {
                $editable->setDataFromResource($serialized);
            } catch (\Throwable) {
            }

            $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran in ' . $class . ' (' . $label . ').');
        }
    }

    public function testControlMultiselectEditableLoadsValues(): void
    {
        $editable = new \Pimcore\Model\Document\Editable\Multiselect();

        $editable->setDataFromResource(serialize(['a', 'b']));

        $this->assertSame(['a', 'b'], $editable->getData());
    }

    public function testControlTableEditableLoadsRows(): void
    {
        $editable = new \Pimcore\Model\Document\Editable\Table();

        $editable->setDataFromResource(serialize([['a', 'b'], ['c', 'd']]));

        $this->assertSame([['a', 'b'], ['c', 'd']], $editable->getData());
    }

    public function testControlLinkEditableLoadsData(): void
    {
        $editable = new \Pimcore\Model\Document\Editable\Link();

        $editable->setDataFromResource(serialize(['text' => 'pd-sec', 'path' => '/pd-sec']));

        $this->assertSame(['text' => 'pd-sec', 'path' => '/pd-sec'], $editable->getData());
    }

    public function testControlRelationEditableLoadsReference(): void
    {
        $editable = new \Pimcore\Model\Document\Editable\Relation();

        $editable->setDataFromResource(serialize(['id' => 1, 'type' => 'asset', 'subtype' => 'folder']));

        $this->assertSame([1, 'folder'], [$editable->getId(), $editable->getSubtype()]);
    }

    public function testControlImageEditableReloadKeepsHotspotAndMarkerItems(): void
    {
        $this->prepareFolder();
        $image = \Pimcore\Model\Asset::create($this->folderId(), [
            'filename' => 'pixel.png',
            'data' => (string) base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='),
        ]);
        $editable = new \Pimcore\Model\Document\Editable\Image();
        $editable->setName('img');

        $editable->setDataFromResource(serialize([
            'id' => $image->getId(),
            'alt' => 'pd-sec',
            'hotspots' => [['name' => 'h', 'data' => [$this->markerItem()]]],
            'marker' => [['name' => 'm', 'data' => [$this->markerItem()]]],
        ]));
        $editmode = $editable->getDataEditmode();

        $this->assertSame('label', $editmode['hotspots'][0]['data'][0]['name']);
        $this->assertSame('label', $editmode['marker'][0]['data'][0]['name']);
    }

    public function testSessionElementWithForeignClassInUnsignedRowIsRejected(): void
    {
        $asset = $this->sessionAsset('sessionaaa.txt');
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), $this->serialized(fn (): mixed => $this->canary()), 'asset-session');

        $loaded = \Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId());

        $this->assertNull($loaded);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading a session element.');
    }

    public function testSessionElementWithoutSignatureIsRejected(): void
    {
        $asset = $this->sessionAsset('sessionaaa.txt');
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), serialize($asset), 'asset-session');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId()));
    }

    public function testSessionElementWithTamperedPayloadIsRejected(): void
    {
        $asset = $this->sessionAsset('sessionaaa.txt');
        \Pimcore\Model\Element\Service::saveElementToSession($asset);
        $stored = (string) \Pimcore\Model\Tool\TmpStore::get($this->sessionKey($asset))?->getData();
        $this->assertStringContainsString('sessionaaa.txt', $stored);
        \Pimcore\Model\Tool\TmpStore::set($this->sessionKey($asset), str_replace('sessionaaa.txt', 'sessionbbb.txt', $stored), 'asset-session');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId()));
    }

    public function testSessionElementSignedForAnotherKeyIsRejected(): void
    {
        $asset = $this->sessionAsset('sessionaaa.txt');
        \Pimcore\Model\Element\Service::saveElementToSession($asset);
        $stored = (string) \Pimcore\Model\Tool\TmpStore::get($this->sessionKey($asset))?->getData();
        $otherKey = \Pimcore\Model\Element\Service::getSessionKey('asset', $asset->getId(), '_other');
        $this->tmpStoreCleanup($otherKey);
        \Pimcore\Model\Tool\TmpStore::set($otherKey, $stored, 'asset-session_other');

        $this->assertNull(\Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId(), '_other'));
    }

    public function testControlSessionElementRoundTripsWhenSavedThroughService(): void
    {
        $asset = $this->sessionAsset('sessionaaa.txt');

        \Pimcore\Model\Element\Service::saveElementToSession($asset);
        $loaded = \Pimcore\Model\Element\Service::getElementFromSession('asset', $asset->getId());

        $this->assertInstanceOf(\Pimcore\Model\Asset::class, $loaded);
        $this->assertSame([$asset->getId(), 'sessionaaa.txt'], [$loaded->getId(), $loaded->getFilename()]);
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
        try {
            $this->errorLogDetail($this->serialized(fn (): mixed => ['q' => 'v', 'gadget' => $this->canary()]));
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while rendering the HTTP error log detail.');
    }

    public function testControlErrorLogDetailShowsLegitimateParameters(): void
    {
        $response = $this->errorLogDetail(serialize(['pd-sec-key' => 'pd-sec-value']));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('pd-sec-key', (string) $response->getContent());
        $this->assertStringContainsString('pd-sec-value', (string) $response->getContent());
    }

    public function testPrintProcessingOptionsFileDoesNotInstantiateForeignClass(): void
    {
        $admin = $this->createAdmin();
        $this->authenticate($admin);
        $file = PIMCORE_SYSTEM_TEMP_DIRECTORY . DIRECTORY_SEPARATOR . 'web2print-processingoptions-987654_' . $admin->getId() . '.psf';
        $this->writeTempFile($file, $this->serialized(fn (): mixed => ['pd-sec' => $this->canary()]));
        $this->resetCanary();

        $options = $this->storedPrintOptions(987654);

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the stored print options.');
        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, $options['pd-sec']);
    }

    public function testControlPrintProcessingOptionsFileKeepsLegitimateOptions(): void
    {
        $admin = $this->createAdmin();
        $this->authenticate($admin);
        $file = PIMCORE_SYSTEM_TEMP_DIRECTORY . DIRECTORY_SEPARATOR . 'web2print-processingoptions-987655_' . $admin->getId() . '.psf';
        $this->writeTempFile($file, serialize(['dpi' => '300', 'color' => true]));

        $this->assertSame(['dpi' => '300', 'color' => true], $this->storedPrintOptions(987655));
    }

    public function testObjectGridConfigFileDoesNotInstantiateForeignClass(): void
    {
        $admin = $this->createAdmin();
        $this->authenticate($admin);
        $file = PIMCORE_CONFIGURATION_DIRECTORY . '/object/grid/1-user_' . $admin->getId() . '.psf';
        $this->writeTempFile($file, $this->serialized(fn (): mixed => ['classId' => 'x', 'gadget' => $this->canary()]));
        $this->resetCanary();

        $this->folderAction();

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the object grid configuration.');
    }

    public function testControlObjectGridConfigFileSelectsSavedClass(): void
    {
        $admin = $this->createAdmin();
        $this->authenticate($admin);
        $classes = \Pimcore\Model\DataObject::getById(1)->getDao()->getClasses();
        $this->assertNotEmpty($classes, 'The root folder needs child objects of at least one class.');
        $classId = $classes[0]->getId();
        $file = PIMCORE_CONFIGURATION_DIRECTORY . '/object/grid/1-user_' . $admin->getId() . '.psf';
        $this->writeTempFile($file, serialize(['classId' => $classId]));

        $data = json_decode((string) $this->folderAction()->getContent(), true);

        $this->assertSame($classId, $data['selectedClass']);
    }

    public function testDashboardConfigFileWithForeignClassIsRejected(): void
    {
        $dashboard = $this->dashboardWithFile($this->serialized(fn (): mixed => $this->canary()));

        try {
            $dashboard->getAllDashboards();
        } catch (\Throwable) {
        }

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the dashboard config.');
    }

    public function testDashboardConfigFileWithNestedForeignClassIsNotInstantiated(): void
    {
        $dashboard = $this->dashboardWithFile($this->serialized(fn (): mixed => ['custom' => ['positions' => [[], []], 'gadget' => $this->canary()]]));

        $dashboard->getAllDashboards();

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the dashboard config.');
    }

    public function testControlDashboardConfigFileLoadsLegitimateConfiguration(): void
    {
        $positions = [[['id' => 1, 'type' => 'pimcore.layout.portlets.modificationStatistic', 'config' => null]], []];
        $dashboard = $this->dashboardWithFile(serialize(['pd-sec-custom' => ['positions' => $positions]]));

        $this->assertSame($positions, $dashboard->getAllDashboards()['pd-sec-custom']['positions']);
    }

    private function errorLogDetail(string $parametersGet): \Symfony\Component\HttpFoundation\Response
    {
        $db = \Pimcore\Db::get();
        $db->delete('http_error_log', ['uri' => self::ERROR_LOG_URI]);
        $this->cleanups[] = static function (): void {
            \Pimcore\Db::get()->delete('http_error_log', ['uri' => self::ERROR_LOG_URI]);
        };
        $db->insert('http_error_log', ['uri' => self::ERROR_LOG_URI, 'code' => 404, 'parametersGet' => $parametersGet, 'date' => time(), 'count' => 1]);
        $this->authenticate($this->createAdmin());
        $this->resetCanary();

        return \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\MiscController::class)->httpErrorLogDetailAction(
            new \Symfony\Component\HttpFoundation\Request(['uri' => self::ERROR_LOG_URI]),
            null,
        );
    }

    private function folderAction(): \Symfony\Component\HttpFoundation\JsonResponse
    {
        return \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\DataObject\DataObjectController::class)->getFolderAction(
            new \Symfony\Component\HttpFoundation\Request(['id' => 1]),
            \Pimcore::getEventDispatcher(),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function storedPrintOptions(int $documentId): array
    {
        $controller = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Controller\Admin\Document\PrintpageController::class);

        return (new \ReflectionMethod($controller, 'getStoredProcessingOptions'))->invoke($controller, $documentId);
    }

    private function phpOperator(string $mode, string $value): \Pimcore\DataObject\GridColumnConfig\Operator\PHP
    {
        $config = new \stdClass();
        $config->label = 'pd-sec';
        $config->mode = $mode;
        $config->childs = [new \Portadesign\PimcoreSecurityPatches\Tests\Support\P2StubGridColumn($value)];

        return new \Pimcore\DataObject\GridColumnConfig\Operator\PHP($config, []);
    }

    private function writeTempFile(string $file, string $contents): void
    {
        $created = [];
        for ($dir = dirname($file); !is_dir($dir); $dir = dirname($dir)) {
            array_unshift($created, $dir);
        }
        if ([] !== $created) {
            mkdir(dirname($file), 0775, true);
        }
        file_put_contents($file, $contents);
        $this->cleanups[] = static function () use ($file, $created): void {
            @unlink($file);
            foreach (array_reverse($created) as $dir) {
                @rmdir($dir);
            }
        };
    }

    private function dashboardWithFile(string $contents): \Pimcore\Helper\Dashboard
    {
        $user = $this->createAdmin();
        $this->authenticate($user);
        $this->writeTempFile(PIMCORE_CONFIGURATION_DIRECTORY . '/portal/dashboards_' . $user->getId() . '.psf', $contents);
        $this->resetCanary();

        return new \Pimcore\Helper\Dashboard($user);
    }

    private function createPage(): int
    {
        $this->prepareFolder();
        $page = new \Pimcore\Model\Document\Page();
        $page->setParentId(1);
        $page->setKey('pd-sec-remaining-page');
        $page->setPublished(false);
        $page->setUserOwner(1);
        $page->setUserModification(1);
        $page->save();
        $id = $page->getId();
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Document::getById($id, ['force' => true])?->delete();
        };

        return $id;
    }

    private function insertTargetingRule(string $conditions, string $actions): int
    {
        $db = \Pimcore\Db::get();
        $db->insert('targeting_rules', ['name' => 'pd-sec-remaining', 'conditions' => $conditions, 'actions' => $actions]);
        $id = (int) $db->lastInsertId();
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Db::get()->delete('targeting_rules', ['id' => $id]);
        };

        return $id;
    }

    private function sessionAsset(string $filename): \Pimcore\Model\Asset
    {
        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->setSession(new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage()));
        $stack = \Pimcore::getContainer()->get('request_stack');
        $stack->push($request);
        $this->cleanups[] = static function () use ($stack): void {
            $stack->pop();
        };

        $this->prepareFolder();
        $asset = \Pimcore\Model\Asset::create($this->folderId(), ['filename' => $filename, 'data' => 'pd-sec-session']);
        $this->cleanups[] = function () use ($asset): void {
            \Pimcore\Model\Element\Service::removeElementFromSession('asset', $asset->getId());
            \Pimcore\Model\Element\Service::removeElementFromSession('asset', $asset->getId(), '_other');
        };

        return $asset;
    }

    private function sessionKey(\Pimcore\Model\Asset $asset): string
    {
        return \Pimcore\Model\Element\Service::getSessionKey('asset', $asset->getId());
    }

    private function tmpStoreCleanup(string $id): void
    {
        $this->cleanups[] = static function () use ($id): void {
            \Pimcore\Model\Tool\TmpStore::delete($id);
        };
    }

    private function tableField(): \Pimcore\Model\DataObject\ClassDefinition\Data\Table
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Table();
        $field->setName('tbl');

        return $field;
    }

    private function markerItem(): \Pimcore\Model\Element\Data\MarkerHotspotItem
    {
        return new \Pimcore\Model\Element\Data\MarkerHotspotItem(['name' => 'label', 'type' => 'input', 'value' => 'v']);
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

    private function prepareFolder(): void
    {
        $this->deleteAssetByPath('/' . self::FOLDER);
        $this->createAssetFolder(parentId: 1, filename: self::FOLDER);
    }

    private function folderId(): int
    {
        return \Pimcore\Model\Asset::getByPath('/' . self::FOLDER)->getId();
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
