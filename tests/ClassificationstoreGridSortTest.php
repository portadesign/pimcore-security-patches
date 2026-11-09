<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-007')]
final class ClassificationstoreGridSortTest extends \PHPUnit\Framework\TestCase
{
    private \Pimcore\Bundle\AdminBundle\Helper\GridHelperService $service;

    private \Pimcore\Model\DataObject\ClassDefinition $class;

    private string $classCacheKey = '';

    private mixed $originalCachedClass = null;

    private bool $classWasCached = false;

    protected function setUp(): void
    {
        $this->service = new \Pimcore\Bundle\AdminBundle\Helper\GridHelperService(\Pimcore::getContainer()->get('event_dispatcher'));

        $real = null;
        foreach ((new \Pimcore\Model\DataObject\ClassDefinition\Listing())->load() as $candidate) {
            if (class_exists('\\Pimcore\\Model\\DataObject\\' . ucfirst($candidate->getName()) . '\\Listing')) {
                $real = $candidate;

                break;
            }
        }

        if (null === $real) {
            $this->markTestSkipped('The host has no data object class with a generated listing.');
        }

        $panel = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Panel();
        $panel->setName('pd-sec-panel');
        $panel->setChildren([
            $this->createStoreField('store'),
            $this->createStoreField('pd_sec_store'),
            (new \Pimcore\Model\DataObject\ClassDefinition\Data\Input())->setName('plain'),
        ]);
        $this->class = clone $real;
        $this->class->setLayoutDefinitions($panel);

        $this->classCacheKey = 'class_' . $real->getId();
        $this->classWasCached = \Pimcore\Cache\RuntimeCache::isRegistered($this->classCacheKey);
        $this->originalCachedClass = $this->classWasCached ? \Pimcore\Cache\RuntimeCache::get($this->classCacheKey) : null;
        \Pimcore\Cache\RuntimeCache::set($this->classCacheKey, $this->class);
    }

    protected function tearDown(): void
    {
        if ('' !== $this->classCacheKey) {
            \Pimcore\Cache\RuntimeCache::set($this->classCacheKey, $this->classWasCached ? $this->originalCachedClass : null);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function injectedSortPropertyProvider(): array
    {
        return [
            'select expression in the field name' => ['~classificationstore~store_x AS pd_sec_marker, 4242 AS pd_sec_probe~1-2'],
            'subquery in the field name' => ['~classificationstore~store_x, (SELECT 4242) AS pd_sec_probe~1-2'],
            'unknown field' => ['~classificationstore~missing~1-2'],
            'field that is not a classification store' => ['~classificationstore~plain~1-2'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('injectedSortPropertyProvider')]
    public function testInjectedSortPropertyNeverReachesTheQuery(string $property): void
    {
        try {
            $list = $this->service->prepareListingForGrid($this->gridParams($property), 'en', $this->admin());
            $sql = $list->getQueryBuilder()->getSQL();
            $this->fail('The sort property was accepted: ' . $sql);
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Invalid classification store column.', $e->getMessage());
        }
    }

    public function testInjectedGroupIdNeverReachesTheJoin(): void
    {
        $list = $this->newListing();
        $this->service->addGridFeatureJoins($list, [['fieldname' => 'store', 'groupId' => '1) OR (4242', 'keyId' => 2, 'language' => 'default']], $this->class, []);

        try {
            $sql = $list->getQueryBuilder()->getSQL();
            $this->fail('The group id was accepted: ' . $sql);
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Invalid classification store column.', $e->getMessage());
        }
    }

    public function testInjectedKeyIdNeverReachesTheAlias(): void
    {
        $list = $this->newListing();
        $this->service->addGridFeatureJoins($list, [['fieldname' => 'store', 'groupId' => 1, 'keyId' => '2 AS pd_sec_probe, 4242', 'language' => 'default']], $this->class, []);

        try {
            $sql = $list->getQueryBuilder()->getSQL();
            $this->fail('The key id was accepted: ' . $sql);
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('Invalid classification store column.', $e->getMessage());
        }
    }

    public function testControlValidSortPropertyBuildsExpectedJoin(): void
    {
        $list = $this->service->prepareListingForGrid($this->gridParams('~classificationstore~store~3-4'), 'en', $this->admin());
        $sql = $list->getQueryBuilder()->getSQL();

        $table = 'object_classificationstore_data_' . $this->class->getId();
        $this->assertStringContainsString('cskey_store_3_4.value AS cskey_store_3_4', $sql);
        $this->assertStringContainsString('LEFT JOIN ' . $table . ' cskey_store_3_4 ON', $sql);
        $this->assertStringContainsString("cskey_store_3_4.fieldname = 'store' and cskey_store_3_4.groupId=3 and cskey_store_3_4.keyId=4 and cskey_store_3_4.language = 'default'", $sql);
        $this->assertStringContainsString('ORDER BY `cskey_store_3_4` ASC', $sql);
    }

    public function testSortOnFieldWithUnderscoreInItsName(): void
    {
        $list = $this->service->prepareListingForGrid($this->gridParams('~classificationstore~pd_sec_store~3-4'), 'en', $this->admin());
        $sql = $list->getQueryBuilder()->getSQL();

        $this->assertStringContainsString('cskey_pd_sec_store_3_4.value AS cskey_pd_sec_store_3_4', $sql);
        $this->assertStringContainsString("cskey_pd_sec_store_3_4.fieldname = 'pd_sec_store'", $sql);
    }

    public function testControlPlainSortDoesNotJoinTheClassificationStore(): void
    {
        $list = $this->service->prepareListingForGrid($this->gridParams('id'), 'en', $this->admin());
        $sql = $list->getQueryBuilder()->getSQL();

        $this->assertStringNotContainsString('cskey_', $sql);
        $this->assertStringContainsString('ORDER BY `oo_id` ASC', $sql);
    }

    private function createStoreField(string $name): \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore
    {
        $field = new \Pimcore\Model\DataObject\ClassDefinition\Data\Classificationstore();
        $field->setName($name);

        return $field;
    }

    private function admin(): \Pimcore\Model\User
    {
        $user = new \Pimcore\Model\User();
        $user->setAdmin(true);

        return $user;
    }

    private function newListing(): \Pimcore\Model\DataObject\Listing\Concrete
    {
        $listClass = '\\Pimcore\\Model\\DataObject\\' . ucfirst($this->class->getName()) . '\\Listing';
        $list = new $listClass();
        \assert($list instanceof \Pimcore\Model\DataObject\Listing\Concrete);

        return $list;
    }

    /**
     * @return array<string, mixed>
     */
    private function gridParams(string $sortProperty): array
    {
        return [
            'folderId' => 1,
            'classId' => $this->class->getId(),
            'sort' => json_encode([['property' => $sortProperty, 'direction' => 'ASC']]),
        ];
    }
}
